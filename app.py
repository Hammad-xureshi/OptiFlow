
# ⚡ SMART CYBERSECURITY THREAT LOGGER ⚡
from flask import Flask, request, session, redirect, render_template_string, url_for, jsonify
import mysql.connector
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime, timedelta
import re
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ----------------------------------------------------------
# Flask setup
# ----------------------------------------------------------
app = Flask(__name__)
app.secret_key = "supersecretkey_insane_2024_hammad"
app.config['SECRET_KEY'] = 'supersecretkey_insane_2024_hammad'

# ----------------------------------------------------------
# 🔥 CONFIGURATION
# ----------------------------------------------------------
DEVELOPMENT_MODE = True  # Set to False for production
ADMIN_PASSWORD = "admin123"  # Default password

# ----------------------------------------------------------
# Rate Limiter Setup
# ----------------------------------------------------------
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["500 per day", "100 per hour"],
    storage_uri="memory://"
)

# ----------------------------------------------------------
# MySQL credentials (CHANGE THESE FOR YOUR SYSTEM)
# ----------------------------------------------------------
DB = dict(
    host="localhost", 
    user="root", 
    password="123",  # ⚠️ CHANGE THIS TO YOUR MYSQL PASSWORD
    database="threat_logger_db"
)

def db(): 
    return mysql.connector.connect(**DB)

# ==========================================================
# DEVICE INTELLIGENCE PARSER
# ==========================================================
def parse_device_info(user_agent):
    """Extract Browser, OS, and Device Type from User-Agent string"""
    ua = user_agent.lower()
    
    # Browser Detection
    if 'edg' in ua:
        browser = 'Edge'
    elif 'chrome' in ua and 'safari' in ua:
        browser = 'Chrome'
    elif 'firefox' in ua:
        browser = 'Firefox'
    elif 'safari' in ua and 'chrome' not in ua:
        browser = 'Safari'
    elif 'opera' in ua or 'opr' in ua:
        browser = 'Opera'
    elif 'msie' in ua or 'trident' in ua:
        browser = 'Internet Explorer'
    else:
        browser = 'Unknown Browser'
    
    # OS Detection
    if 'windows nt 10' in ua:
        os_name = 'Windows 10/11'
    elif 'windows nt 6.3' in ua:
        os_name = 'Windows 8.1'
    elif 'windows nt 6.2' in ua:
        os_name = 'Windows 8'
    elif 'windows nt 6.1' in ua:
        os_name = 'Windows 7'
    elif 'windows' in ua:
        os_name = 'Windows (Other)'
    elif 'mac os x' in ua or 'macos' in ua:
        os_name = 'macOS'
    elif 'android' in ua:
        os_name = 'Android'
    elif 'iphone' in ua or 'ipad' in ua:
        os_name = 'iOS'
    elif 'linux' in ua:
        os_name = 'Linux'
    elif 'ubuntu' in ua:
        os_name = 'Ubuntu'
    else:
        os_name = 'Unknown OS'
    
    # Device Type Detection
    if 'mobile' in ua or 'android' in ua or 'iphone' in ua:
        device_type = 'Mobile'
    elif 'tablet' in ua or 'ipad' in ua:
        device_type = 'Tablet'
    else:
        device_type = 'Desktop'
    
    return browser, os_name, device_type

# ==========================================================
# PASSWORD FUNCTIONS
# ==========================================================
def hash_password(password):
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(password, hashed):
    """Verify password against hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except:
        return False

# ==========================================================
# IP BLACKLIST FUNCTIONS
# ==========================================================
def is_ip_blacklisted(ip):
    """Check if IP is in blacklist"""
    try:
        conn = db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM Blacklist WHERE IPAddress = %s AND IsActive = TRUE", (ip,))
        result = cur.fetchone()
        conn.close()
        return result is not None
    except:
        return False

def add_to_blacklist(ip, reason, blocked_by="Admin"):
    """Add IP to blacklist"""
    try:
        conn = db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO Blacklist (IPAddress, Reason, BlockedBy) 
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE 
            Reason = %s, BlockedBy = %s, BlockedAt = NOW(), IsActive = TRUE
        """, (ip, reason, blocked_by, reason, blocked_by))
        conn.commit()
        
        # Log this action
        cur.execute("""
            INSERT INTO Logs (UserID, ActionType, Timestamp, IPAddress, Browser, OS, DeviceType)
            VALUES (1, 'IPBlocked', NOW(), %s, 'System', 'System', 'System')
        """, (ip,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error adding to blacklist: {e}")
        return False

def remove_from_blacklist(ip):
    """Remove IP from blacklist"""
    try:
        conn = db()
        cur = conn.cursor()
        cur.execute("UPDATE Blacklist SET IsActive = FALSE WHERE IPAddress = %s", (ip,))
        conn.commit()
        
        # Log this action
        cur.execute("""
            INSERT INTO Logs (UserID, ActionType, Timestamp, IPAddress, Browser, OS, DeviceType)
            VALUES (1, 'IPUnblocked', NOW(), %s, 'System', 'System', 'System')
        """, (ip,))
        conn.commit()
        conn.close()
        return True
    except:
        return False

def get_blacklist():
    """Get all blacklisted IPs"""
    try:
        conn = db()
        cur = conn.cursor()
        cur.execute("""
            SELECT BlacklistID, IPAddress, Reason, BlockedBy, BlockedAt, IsActive 
            FROM Blacklist 
            ORDER BY BlockedAt DESC
        """)
        result = cur.fetchall()
        conn.close()
        return result
    except:
        return []

def auto_blacklist_check(ip):
    """Auto-blacklist IP if too many failed attempts"""
    
    # Disable in development mode
    if DEVELOPMENT_MODE:
        print(f"⚠️ Development Mode: Auto-blocking disabled for {ip}")
        return False
    
    # Whitelist localhost
    whitelist = ['127.0.0.1', 'localhost', '::1', '0.0.0.0']
    if ip in whitelist:
        return False
    
    try:
        conn = db()
        cur = conn.cursor()
        
        cur.execute("""
            SELECT COUNT(*) FROM LoginAttempts 
            WHERE IPAddress = %s 
            AND Success = FALSE 
            AND AttemptTime > DATE_SUB(NOW(), INTERVAL 10 MINUTE)
        """, (ip,))
        
        failed_count = cur.fetchone()[0]
        conn.close()
        
        # If more than 10 failed attempts, auto-block
        if failed_count >= 10:
            add_to_blacklist(ip, f"Auto-blocked: {failed_count} failed login attempts", "System Auto-Block")
            return True
        
        return False
    except:
        return False

# ==========================================================
# LOGIN ATTEMPT TRACKING
# ==========================================================
def log_login_attempt(ip, success, user_agent):
    """Track login attempts"""
    try:
        conn = db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO LoginAttempts (IPAddress, Success, UserAgent, AttemptTime)
            VALUES (%s, %s, %s, NOW())
        """, (ip, success, user_agent))
        conn.commit()
        conn.close()
    except:
        pass

# ==========================================================
# DATABASE HELPERS
# ==========================================================
def record_visit(ip, user_agent):
    """Record dashboard visit with device information"""
    try:
        conn = db()
        cur = conn.cursor()
        if not session.get("visited_logged"):
            browser, os_name, device_type = parse_device_info(user_agent)
            cur.execute("""INSERT INTO Logs 
                          (UserID, ActionType, Timestamp, IPAddress, Browser, OS, DeviceType) 
                          VALUES (%s, %s, NOW(), %s, %s, %s, %s)""",
                       (1, "DashboardVisit", ip, browser, os_name, device_type))
            conn.commit()
            session["visited_logged"] = True
        conn.close()
    except Exception as e:
        print(f"Error recording visit: {e}")

def fetch_recent_logs(limit=15):
    """Fetch recent logs WITH device info"""
    try:
        conn = db()
        cur = conn.cursor()
        cur.execute("""SELECT l.LogID, u.Name, u.Role, l.ActionType, l.Timestamp, l.IPAddress,
                       l.Browser, l.OS, l.DeviceType
                       FROM Logs l JOIN Users u ON l.UserID = u.UserID
                       ORDER BY l.Timestamp DESC LIMIT %s""", (limit,))
        r = cur.fetchall()
        conn.close()
        return r
    except:
        return []

def fetch_alerts():
    """Fetch alerts WITH device info"""
    try:
        conn = db()
        cur = conn.cursor()
        cur.execute("""SELECT a.AlertID, l.LogID, u.Name, l.ActionType, l.Timestamp, l.IPAddress,
                       a.RiskScore, a.ThreatType, l.Browser, l.OS, l.DeviceType
                       FROM Alerts a
                       JOIN Logs l ON a.LogID = l.LogID
                       JOIN Users u ON l.UserID = u.UserID
                       ORDER BY a.RiskScore DESC LIMIT 10""")
        rows = cur.fetchall()
        conn.close()
        return rows
    except:
        return []

def insert_alerts(threats):
    if threats.empty: return
    try:
        conn = db()
        cur = conn.cursor()
        for _, r in threats.iterrows():
            cur.execute("INSERT INTO Alerts (LogID, RiskScore, ThreatType) VALUES (%s, %s, %s)",
                       (int(r.LogID), float(r.RiskScore), r.ThreatType))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error inserting alerts: {e}")

def get_device_analytics():
    """Get device distribution statistics"""
    try:
        conn = db()
        cur = conn.cursor()
        
        # Browser stats
        cur.execute("SELECT Browser, COUNT(*) as count FROM Logs GROUP BY Browser ORDER BY count DESC")
        browsers = dict(cur.fetchall())
        
        # OS stats
        cur.execute("SELECT OS, COUNT(*) as count FROM Logs GROUP BY OS ORDER BY count DESC")
        os_stats = dict(cur.fetchall())
        
        # Device type stats
        cur.execute("SELECT DeviceType, COUNT(*) as count FROM Logs GROUP BY DeviceType ORDER BY count DESC")
        devices = dict(cur.fetchall())
        
        conn.close()
        return browsers, os_stats, devices
    except:
        return {}, {}, {}

# ==========================================================
# ML DETECTION
# ==========================================================
def prepare_for_ml(rows):
    """Prepare data for ML with device features"""
    df = pd.DataFrame(rows, columns=["LogID", "Name", "Role", "ActionType", "Timestamp", 
                                     "IPAddress", "Browser", "OS", "DeviceType"])
    if df.empty: return df, pd.DataFrame()
    
    df["Hour"] = df["Timestamp"].apply(lambda t: t.hour)
    
    # Action mapping
    a_map = {"Login": 0, "FileAccess": 1, "SuspiciousQuery": 2, "DashboardVisit": 3}
    df["ActionCode"] = df["ActionType"].map(a_map).fillna(4)
    
    # IP numeric
    df["IPNumeric"] = df["IPAddress"].apply(lambda ip: int(ip.split(".")[-1]) if "." in ip else 0)
    
    # Device Type encoding
    device_map = {"Desktop": 0, "Mobile": 1, "Tablet": 2}
    df["DeviceCode"] = df["DeviceType"].map(device_map).fillna(0)
    
    # Browser encoding
    browser_map = {"Chrome": 0, "Firefox": 1, "Safari": 2, "Edge": 3, "Opera": 4, "Unknown Browser": 5}
    df["BrowserCode"] = df["Browser"].map(browser_map).fillna(5)
    
    # Enhanced feature set
    X = df[["Hour", "ActionCode", "IPNumeric", "DeviceCode", "BrowserCode"]]
    return df, X

def detect_anomalies(df, X):
    """Detect anomalies using enhanced features"""
    if X.empty: return df.head(0)
    try:
        model = IsolationForest(n_estimators=150, contamination=0.15, random_state=42).fit(X)
        raw = -model.decision_function(X)
        df["RiskScore"] = 100 * (raw - raw.min()) / (raw.max() - raw.min())
        df["Anomaly"] = model.predict(X)
        
        q75, q50 = np.quantile(df["RiskScore"], [0.75, 0.5])
        
        def level(s):
            if s >= q75: return "High Risk"
            elif s >= q50: return "Medium Risk"
            return "Low Risk"
        
        df["ThreatType"] = df["RiskScore"].apply(level)
        return df[df["Anomaly"] == -1]
    except:
        return df.head(0)

# ==========================================================
# MIDDLEWARE: IP BLACKLIST CHECK
# ==========================================================
@app.before_request
def check_blacklist():
    """Block blacklisted IPs before processing any request"""
    
    # Skip in development mode
    if DEVELOPMENT_MODE:
        return None
    
    # Skip check for static files and emergency endpoint
    if request.path.startswith('/static') or request.path.startswith('/emergency'):
        return None
    
    ip = request.remote_addr
    
    # Whitelist localhost
    if ip in ['127.0.0.1', 'localhost', '::1', '0.0.0.0']:
        return None
    
    if is_ip_blacklisted(ip):
        return render_template_string(BLOCKED_PAGE, ip=ip)

# ==========================================================
# ROUTES
# ==========================================================
@app.route("/", methods=["GET", "POST"])
@limiter.limit("20 per minute")
def login():
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    
    if request.method == "POST":
        password = request.form.get("password")
        
        print(f"\n{'='*60}")
        print(f"🔍 LOGIN ATTEMPT")
        print(f"   IP Address: {ip}")
        print(f"   Entered Password: {password}")
        print(f"   Development Mode: {DEVELOPMENT_MODE}")
        print(f"{'='*60}\n")
        
        login_success = False
        
        try:
            conn = db()
            cur = conn.cursor()
            cur.execute("SELECT Password FROM Users WHERE UserID = 1")
            result = cur.fetchone()
            conn.close()
            
            if result and result[0]:
                stored_password = result[0]
                print(f"🔐 Stored Password: {stored_password}")
                
                # Check if bcrypt hash
                if stored_password.startswith('$2b$') or stored_password.startswith('$2a$'):
                    print("🔒 Verifying bcrypt hash...")
                    login_success = verify_password(password, stored_password)
                else:
                    # Plain text comparison
                    print("📝 Plain text comparison...")
                    login_success = (password.strip() == stored_password.strip())
            else:
                # Fallback to default password
                print("⚠️ Using default password")
                login_success = (password == ADMIN_PASSWORD)
            
            print(f"{'✅ LOGIN SUCCESS' if login_success else '❌ LOGIN FAILED'}\n")
            
        except Exception as e:
            print(f"🚨 Database error: {e}")
            login_success = (password == ADMIN_PASSWORD)
        
        if login_success:
            log_login_attempt(ip, True, user_agent)
            session["logged"] = True
            session.pop("visited_logged", None)
            return redirect("/dashboard")
        else:
            log_login_attempt(ip, False, user_agent)
            
            if not DEVELOPMENT_MODE:
                if auto_blacklist_check(ip):
                    return render_template_string(BLOCKED_PAGE, ip=ip)
            
            error_msg = """
            <div style='text-align:center; margin-top:50px; font-family:Orbitron; background:#0a0a0a; padding:40px; border:1px solid #333; max-width:600px; margin:50px auto;'>
                <h3 style='color:#ff003c; margin:0;'>⚠️ ACCESS DENIED!</h3>
                <p style='color:#999; margin-top:20px;'>Invalid password entered.</p>
                <div style='background:rgba(204,255,0,0.1); border:1px solid #ccff00; padding:15px; margin:30px auto; max-width:400px;'>
                    <p style='color:#ccff00; font-size:0.9em; margin:5px;'>
                        <strong>Default Password:</strong> admin123
                    </p>
                </div>
                <a href='/' style='color:#7a00ff; text-decoration:none; margin-top:20px; display:inline-block; border:1px solid #7a00ff; padding:10px 30px;'>
                    ← TRY AGAIN
                </a>
            </div>
            """
            return error_msg + LOGIN_PAGE
    
    return LOGIN_PAGE

@app.route("/dashboard")
@limiter.limit("30 per minute")
def dashboard():
    if not session.get("logged"): 
        return redirect("/")
    
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    
    record_visit(ip, user_agent)
    browser, os_name, device_type = parse_device_info(user_agent)
    
    logs = fetch_recent_logs()
    df, X = prepare_for_ml(logs)
    threats = detect_anomalies(df, X)
    insert_alerts(threats)
    
    alerts = fetch_alerts()
    ip_counts = df["IPAddress"].value_counts().to_dict() if not df.empty else {}
    browsers, os_stats, devices = get_device_analytics()
    blacklist = get_blacklist()
    
    try:
        conn = db()
        cur = conn.cursor()
        cur.execute("""
            SELECT IPAddress, Success, AttemptTime 
            FROM LoginAttempts 
            ORDER BY AttemptTime DESC 
            LIMIT 20
        """)
        login_attempts = cur.fetchall()
        conn.close()
    except:
        login_attempts = []
    
    return render_template_string(DASHBOARD_HTML, 
                                  logs=logs, 
                                  alerts=alerts, 
                                  ip=ip,
                                  browser=browser,
                                  os_name=os_name,
                                  device_type=device_type,
                                  ip_counts=ip_counts,
                                  browsers=browsers,
                                  os_stats=os_stats,
                                  devices=devices,
                                  blacklist=blacklist,
                                  login_attempts=login_attempts)

@app.route("/log/<int:logid>")
def log_detail(logid):
    if not session.get("logged"): 
        return redirect("/")
    
    try:
        conn = db()
        cur = conn.cursor()
        cur.execute("""SELECT l.LogID, u.Name, u.Role, l.ActionType, l.Timestamp, l.IPAddress,
                       l.Browser, l.OS, l.DeviceType
                       FROM Logs l JOIN Users u ON l.UserID = u.UserID
                       WHERE l.LogID = %s""", (logid,))
        log = cur.fetchone()
        
        cur.execute("SELECT AlertID, RiskScore, ThreatType FROM Alerts WHERE LogID = %s", (logid,))
        alerts = cur.fetchall()
        conn.close()
    except:
        log = None
        alerts = []
    
    return render_template_string(LOG_DETAIL_HTML, log=log, alerts=alerts)

# ==========================================================
# IP BLACKLIST MANAGEMENT API
# ==========================================================
@app.route("/api/blacklist/add", methods=["POST"])
def api_add_blacklist():
    if not session.get("logged"):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    
    ip = request.form.get("ip")
    reason = request.form.get("reason", "Manually blocked by admin")
    
    if not ip:
        return jsonify({"success": False, "message": "IP address required"})
    
    success = add_to_blacklist(ip, reason, "Admin")
    
    if success:
        return jsonify({"success": True, "message": f"IP {ip} blocked successfully"})
    else:
        return jsonify({"success": False, "message": "Failed to block IP"})

@app.route("/api/blacklist/remove", methods=["POST"])
def api_remove_blacklist():
    if not session.get("logged"):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    
    ip = request.form.get("ip")
    
    if not ip:
        return jsonify({"success": False, "message": "IP address required"})
    
    success = remove_from_blacklist(ip)
    
    if success:
        return jsonify({"success": True, "message": f"IP {ip} unblocked successfully"})
    else:
        return jsonify({"success": False, "message": "Failed to unblock IP"})

# ==========================================================
# EMERGENCY UNBLOCK ENDPOINT (Development Only)
# ==========================================================
@app.route("/emergency/unblock")
def emergency_unblock():
    """Emergency endpoint to unblock current IP"""
    if DEVELOPMENT_MODE:
        ip = request.remote_addr
        try:
            conn = db()
            cur = conn.cursor()
            cur.execute("DELETE FROM Blacklist WHERE IPAddress = %s", (ip,))
            cur.execute("DELETE FROM LoginAttempts WHERE IPAddress = %s", (ip,))
            conn.commit()
            conn.close()
            return f"""
            <div style='text-align:center; margin-top:100px; font-family:Orbitron; background:#0a0a0a; padding:40px; border:1px solid #ccff00;'>
                <h2 style='color:#ccff00;'>✅ YOUR IP HAS BEEN UNBLOCKED</h2>
                <p style='color:#fff; margin:20px; font-size:1.2em;'>{ip}</p>
                <p style='color:#999;'>You can now login again</p>
                <a href='/' style='color:#7a00ff; text-decoration:none; border:1px solid #7a00ff; padding:10px 30px; display:inline-block; margin-top:20px;'>
                    ← Back to Login
                </a>
            </div>
            """
        except Exception as e:
            return f"<h3 style='color:red; text-align:center; margin-top:100px;'>Error: {e}</h3>"
    else:
        return "<h3 style='color:red; text-align:center; margin-top:100px;'>Not available in production mode</h3>"

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ==========================================================
# HTML TEMPLATES WITH ANIMATED BACKGROUNDS
# ==========================================================

BLOCKED_PAGE = """<!DOCTYPE html>
<html lang='en'><head><meta charset='UTF-8'><title>ACCESS DENIED</title>
<link href='https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&display=swap' rel='stylesheet'>
<style>
body {
    margin:0; height:100vh;
    background: #0a0a0a;
    display: flex; align-items: center; justify-content: center;
    font-family: 'Orbitron', sans-serif; color: #ff003c;
    overflow: hidden;
    position: relative;
}

.bg-layer {
    position: fixed;
    top: 0; left: 0;
    width: 100%; height: 100%;
    z-index: -1;
    background: linear-gradient(135deg, #0a0a0a 0%, #1a0000 50%, #0a0a0a 100%);
    background-size: 400% 400%;
    animation: bgShift 10s ease infinite;
}

@keyframes bgShift {
    0%, 100% { background-position: 0% 50%; }
    50% { background-position: 100% 50%; }
}

.danger-orb {
    position: fixed;
    width: 500px; height: 500px;
    border-radius: 50%;
    background: radial-gradient(circle, rgba(255, 0, 60, 0.3) 0%, transparent 70%);
    filter: blur(80px);
    animation: orbPulse 4s ease-in-out infinite;
    z-index: -1;
}

@keyframes orbPulse {
    0%, 100% { transform: scale(1); opacity: 0.3; }
    50% { transform: scale(1.2); opacity: 0.5; }
}

.scanline {
    position: fixed;
    top: 0; left: 0;
    width: 100%; height: 100%;
    background: linear-gradient(transparent 0%, rgba(255, 0, 60, 0.05) 50%, transparent 100%);
    background-size: 100% 4px;
    animation: scan 6s linear infinite;
    z-index: -1;
    pointer-events: none;
}

@keyframes scan {
    0% { background-position: 0 0; }
    100% { background-position: 0 100%; }
}

.container {
    text-align: center; padding: 40px;
    border: 2px solid #ff003c;
    background: rgba(0,0,0,0.9);
    box-shadow: 0 0 50px rgba(255, 0, 60, 0.5);
    animation: pulse 2s infinite;
    position: relative;
    z-index: 1;
    backdrop-filter: blur(10px);
}

@keyframes pulse {
    0%, 100% { box-shadow: 0 0 20px rgba(255, 0, 60, 0.3); }
    50% { box-shadow: 0 0 50px rgba(255, 0, 60, 0.8); }
}

h1 {
    font-size: 4em; margin: 0;
    text-shadow: 0 0 20px #ff003c, 0 0 40px #ff003c;
    animation: textGlow 2s ease-in-out infinite;
}

@keyframes textGlow {
    0%, 100% { text-shadow: 0 0 10px #ff003c; }
    50% { text-shadow: 0 0 30px #ff003c, 0 0 50px #ff003c; }
}

.skull {
    font-size: 6em; margin: 20px 0;
    animation: shake 0.5s infinite;
    filter: drop-shadow(0 0 20px #ff003c);
}

@keyframes shake {
    0%, 100% { transform: rotate(-5deg); }
    50% { transform: rotate(5deg); }
}

p { font-size: 1.2em; margin: 20px 0; }

.ip { 
    color: #fff; 
    background: rgba(255, 0, 60, 0.2);
    padding: 10px 20px;
    border-left: 3px solid #ff003c;
    animation: ipBlink 1.5s ease-in-out infinite;
}

@keyframes ipBlink {
    0%, 100% { border-left-color: #ff003c; }
    50% { border-left-color: #ff6060; }
}

a {
    color: #ccff00;
    text-decoration: none;
    border: 1px solid #ccff00;
    padding: 10px 20px;
    display: inline-block;
    margin-top: 20px;
    transition: 0.3s;
    position: relative;
    overflow: hidden;
}

a::before {
    content: '';
    position: absolute;
    top: 0; left: -100%;
    width: 100%; height: 100%;
    background: rgba(204, 255, 0, 0.2);
    transition: 0.3s;
}

a:hover::before {
    left: 100%;
}

a:hover {
    background: #ccff00;
    color: #000;
    box-shadow: 0 0 20px #ccff00;
}
</style></head>
<body>
<div class='bg-layer'></div>
<div class='danger-orb' style='top: 20%; left: 10%;'></div>
<div class='danger-orb' style='bottom: 20%; right: 10%;'></div>
<div class='scanline'></div>

<div class='container'>
    <div class='skull'>☠️</div>
    <h1>ACCESS DENIED</h1>
    <p>Your IP address has been <strong>BLACKLISTED</strong></p>
    <div class='ip'>{{ ip }}</div>
    <p style='margin-top:30px; font-size:0.9em; color:#999;'>
        Contact system administrator or use emergency unblock
    </p>
    <a href='/emergency/unblock'>🔓 EMERGENCY UNBLOCK</a>
</div>
</body></html>"""

LOGIN_PAGE = """<!DOCTYPE html>
<html lang='en'> 
<head> 
    <meta charset='UTF-8'> 
    <title>INSANE // ACCESS PORTAL</title> 
    <link href='https://fonts.googleapis.com/css2?family=Orbitron:wght@600;900&family=Share+Tech+Mono&display=swap' rel='stylesheet'> 
    <style> 
        :root{ 
            --bg:#030303; 
            --acid:#ccff00; 
            --purple:#7a00ff; 
            --grid:#1a1a1a; 
        } 
        
        html,body{ 
            height:100%;
            margin:0;
            background-color:var(--bg); 
            font-family:'Share Tech Mono',monospace; 
            color:#fff;
            overflow:hidden;
            position: relative;
        }
        
        .bg-animation {
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            z-index: -3;
            background: linear-gradient(45deg, #030303 0%, #0a0a0a 25%, #030303 50%, #0a0a0a 75%, #030303 100%);
            background-size: 400% 400%;
            animation: gradientFlow 15s ease infinite;
        }
        
        @keyframes gradientFlow {
            0%, 100% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
        }
        
        .grid-layer {
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            background-image: 
                linear-gradient(rgba(204, 255, 0, 0.05) 1px, transparent 1px), 
                linear-gradient(90deg, rgba(204, 255, 0, 0.05) 1px, transparent 1px);
            background-size: 100px 100px;
            animation: gridMove 20s linear infinite;
            z-index: -2;
        }
        
        @keyframes gridMove {
            0% { background-position: 0 0; }
            100% { background-position: 100px 100px; }
        }
        
        .particles {
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            z-index: -1;
            overflow: hidden;
        }
        
        .particle {
            position: absolute;
            width: 2px; height: 2px;
            background: var(--acid);
            box-shadow: 0 0 10px var(--acid);
            animation: particleFloat 20s linear infinite;
        }
        
        @keyframes particleFloat {
            0% { transform: translateY(100vh) translateX(0); opacity: 0; }
            10% { opacity: 1; }
            90% { opacity: 1; }
            100% { transform: translateY(-100vh) translateX(100px); opacity: 0; }
        }
        
        .particle:nth-child(odd) { background: var(--purple); box-shadow: 0 0 10px var(--purple); }
        .particle:nth-child(1) { left: 10%; animation-delay: 0s; }
        .particle:nth-child(2) { left: 20%; animation-delay: 3s; }
        .particle:nth-child(3) { left: 30%; animation-delay: 6s; }
        .particle:nth-child(4) { left: 40%; animation-delay: 9s; }
        .particle:nth-child(5) { left: 50%; animation-delay: 12s; }
        .particle:nth-child(6) { left: 60%; animation-delay: 15s; }
        .particle:nth-child(7) { left: 70%; animation-delay: 2s; }
        .particle:nth-child(8) { left: 80%; animation-delay: 5s; }
        .particle:nth-child(9) { left: 90%; animation-delay: 8s; }
        .particle:nth-child(10) { left: 15%; animation-delay: 11s; }
        
        .glow-orb {
            position: fixed;
            width: 600px; height: 600px;
            border-radius: 50%;
            background: radial-gradient(circle, rgba(204, 255, 0, 0.15) 0%, transparent 70%);
            filter: blur(80px);
            animation: orbMove 15s ease-in-out infinite;
            z-index: -1;
        }
        
        @keyframes orbMove {
            0%, 100% { top: 20%; left: 10%; }
            50% { top: 60%; left: 80%; }
        }
        
        .glow-orb.purple {
            background: radial-gradient(circle, rgba(122, 0, 255, 0.15) 0%, transparent 70%);
            animation: orbMove2 20s ease-in-out infinite;
        }
        
        @keyframes orbMove2 {
            0%, 100% { bottom: 20%; right: 10%; }
            50% { bottom: 60%; right: 70%; }
        }
        
        .scanline {
            position: fixed;
            top: 0; left: 0;
            width: 100%; height: 100%;
            background: linear-gradient(transparent 0%, rgba(204, 255, 0, 0.03) 50%, transparent 100%);
            background-size: 100% 4px;
            animation: scan 8s linear infinite;
            z-index: -1;
            pointer-events: none;
        }
        
        @keyframes scan {
            0% { background-position: 0 0; }
            100% { background-position: 0 100%; }
        }
        
        .topbar{
            position:absolute;
            top:0; left:0;
            width:100%;
            display:flex;
            justify-content:space-between;
            align-items:center;
            padding:26px 60px;
            box-sizing:border-box;
            font-size:0.8em;
            letter-spacing:2px;
            color:#666;
            z-index:10;
            backdrop-filter: blur(5px);
            background: rgba(0, 0, 0, 0.3);
        }
        
        .logo{
            font-family:'Orbitron';
            font-weight:900;
            color:#fff;
            letter-spacing:4px;
            user-select:none;
            text-shadow: 0 0 10px var(--acid);
            animation: logoGlow 3s ease-in-out infinite;
        }
        
        @keyframes logoGlow {
            0%, 100% { text-shadow: 0 0 5px var(--acid); }
            50% { text-shadow: 0 0 20px var(--acid), 0 0 30px var(--acid); }
        }
        
        .nav span{
            margin-left:20px;
            color:#444;
            cursor:pointer;
            transition:.3s;
        }
        .nav span:hover{
            color:var(--acid);
            text-shadow: 0 0 10px var(--acid);
        }

        .main{
            height:100%;
            display:flex;
            align-items:center;
            justify-content:center;
            flex-direction:column;
            text-align:center;
            z-index:2;
            position: relative;
        }

        h1{
            font-family:'Orbitron',sans-serif;
            font-weight:900;
            font-size:5.5rem;
            line-height:0.9;
            margin:0;
            text-transform:uppercase;
            color:var(--acid);
            text-shadow:0 0 20px rgba(204,255,0,0.5), 0 0 40px rgba(204,255,0,0.3);
            user-select:none;
            animation: titlePulse 3s ease-in-out infinite;
        }
        
        @keyframes titlePulse {
            0%, 100% { 
                text-shadow: 0 0 10px rgba(204,255,0,0.5), 0 0 20px rgba(204,255,0,0.3); 
                transform: scale(1);
            }
            50% { 
                text-shadow: 0 0 30px rgba(204,255,0,0.8), 0 0 50px rgba(204,255,0,0.5); 
                transform: scale(1.02);
            }
        }
        
        h1 .outline{
            color:transparent;
            -webkit-text-stroke:2px var(--acid);
            animation: outlineGlow 3s ease-in-out infinite;
        }
        
        @keyframes outlineGlow {
            0%, 100% { filter: drop-shadow(0 0 5px var(--acid)); }
            50% { filter: drop-shadow(0 0 15px var(--acid)); }
        }

        form{
            margin-top:40px;
            position:relative;
            z-index:5;
            padding:30px 25px 35px 25px;
            background:rgba(0,0,0,0.8);
            backdrop-filter: blur(10px);
            border:1px solid rgba(204, 255, 0, 0.2);
            width:320px;
            box-shadow:0 0 50px rgba(0,0,0,0.9), 0 0 30px rgba(204, 255, 0, 0.1);
            display:flex;
            flex-direction:column;
            align-items:center;
            pointer-events:auto;
            animation: formFloat 6s ease-in-out infinite;
        }
        
        @keyframes formFloat {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-10px); }
        }
        
        form::before,form::after{
            content:'';
            position:absolute;
            width:20px; height:20px;
            border:2px solid var(--purple);
            transition:.3s;
            pointer-events:none;
        }
        form::before{
            top:-2px; left:-2px;
            border-right:none;
            border-bottom:none;
            animation: cornerGlow1 2s ease-in-out infinite;
        }
        form::after{
            bottom:-2px; right:-2px;
            border-left:none;
            border-top:none;
            animation: cornerGlow2 2s ease-in-out infinite;
        }
        
        @keyframes cornerGlow1 {
            0%, 100% { box-shadow: 0 0 5px var(--purple); }
            50% { box-shadow: 0 0 15px var(--purple); }
        }
        
        @keyframes cornerGlow2 {
            0%, 100% { box-shadow: 0 0 5px var(--purple); }
            50% { box-shadow: 0 0 15px var(--purple); }
        }
        
        form:hover::before,form:hover::after{
            width:100%;
            height:100%;
            opacity:.5;
        }

        input[type=password]{
            width:240px;
            background:rgba(10,10,10,0.7);
            border:none;
            border-bottom:2px solid #333;
            padding:12px;
            margin-bottom:20px;
            color:#fff;
            font-size:1.1em;
            text-align:center;
            transition:border-color .3s, box-shadow .3s;
            outline:none;
            z-index:6;
            position:relative;
        }
        input[type=password]::placeholder{
            color:#555;
            letter-spacing:2px;
        }
        input[type=password]:focus{
            border-color:var(--acid);
            box-shadow:0 8px 20px -10px rgba(204,255,0,0.5);
            background: rgba(10,10,10,0.9);
        }

        input[type=submit]{
            background:var(--acid);
            color:#000;
            font-family:'Orbitron';
            font-weight:700;
            border:none;
            padding:12px 40px;
            cursor:pointer;
            letter-spacing:1px;
            clip-path:polygon(8% 0,100% 0,100% 70%,92% 100%,0 100%,0 30%);
            transition:.2s;
            position: relative;
            overflow: hidden;
        }
        
        input[type=submit]::before {
            content: '';
            position: absolute;
            top: 50%; left: 50%;
            width: 0; height: 0;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.5);
            transform: translate(-50%, -50%);
            transition: width 0.6s, height 0.6s;
        }
        
        input[type=submit]:hover::before {
            width: 300px;
            height: 300px;
        }
        
        input[type=submit]:hover{
            background:#fff;
            box-shadow:0 0 30px var(--acid);
            transform:translateY(2px);
        }

        .bottom{
            position:absolute;
            bottom:0; left:0;
            width:100%;
            display:flex;
            justify-content:space-between;
            align-items:flex-end;
            padding:25px 60px;
            font-size:0.8em;
            letter-spacing:2px;
            box-sizing:border-box;
            color:#999;
            backdrop-filter: blur(5px);
            background: rgba(0, 0, 0, 0.3);
        }
        .left-col{
            border-left:2px solid var(--purple);
            padding-left:15px;
        }
        .left-col span{
            color:var(--purple);
            animation: nameGlow 2s ease-in-out infinite;
        }
        
        @keyframes nameGlow {
            0%, 100% { text-shadow: 0 0 5px var(--purple); }
            50% { text-shadow: 0 0 15px var(--purple); }
        }
        
        .right-col{
            text-align:right;
            color:var(--acid);
            font-family:'Orbitron';
            letter-spacing:3px;
        }
        .right-col .arrow{
            font-size:1.8em;
            color:var(--purple);
            transform:rotate(45deg);
            display:block;
            margin-bottom:6px;
            user-select:none;
            animation: arrowSpin 4s linear infinite;
        }
        
        @keyframes arrowSpin {
            0% { transform: rotate(45deg); }
            25% { transform: rotate(90deg); }
            50% { transform: rotate(135deg); }
            75% { transform: rotate(180deg); }
            100% { transform: rotate(45deg); }
        }
    </style>
</head> 

<body>
    <div class='bg-animation'></div>
    <div class='grid-layer'></div>
    <div class='glow-orb'></div>
    <div class='glow-orb purple'></div>
    <div class='scanline'></div>
    
    <div class='particles'>
        <div class='particle'></div>
        <div class='particle'></div>
        <div class='particle'></div>
        <div class='particle'></div>
        <div class='particle'></div>
        <div class='particle'></div>
        <div class='particle'></div>
        <div class='particle'></div>
        <div class='particle'></div>
        <div class='particle'></div>
    </div>
    
   <div class='topbar'>
    <div class='logo'>INSANE // SECURE</div>
    <div class='nav'>
        <a href='https://www.instagram.com/hammad__qureshi110?igsh=dzFha21iYm44b3Qw' target='_blank'>/ INSTAGRAM</a>
        <a href='https://www.linkedin.com/in/hammad-naeem-b5762a384/' target='_blank'>/ LINKEDIN</a>
        <a href='https://twitter.com' target='_blank'>/ TWITTER</a>
        <a href='https://discord.com' target='_blank'>/ DISCORD</a>
        <a href='https://opensea.io' target='_blank'>/ OPENSEA</a>
    </div>
</div>
    
    <div class='main'> 
        <h1>SECURE<br><span class='outline'>ACCESS</span><br>PORTAL</h1> 
        <form method='POST'> 
            <input type='password' name='password' placeholder='ENTER ACCESS KEY' required autocomplete='off'> 
            <input type='submit' value='INITIATE'> 
        </form> 
    </div>
    
    <div class='bottom'> 
        <div class='left-col'> 
            Made BY <br><span>Hammad Naeem</span> 
        </div> 
        <div class='right-col'> 
            <span class='arrow'>&#10138;</span> 
            INVEST IN THE<br>FUTURE 
        </div> 
    </div>
</body> 
</html>"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang='en'><head> <meta http-equiv='refresh' content='15'><meta charset='UTF-8'> <title>INSANE // SECURITY DASHBOARD</title> <script src='https://cdn.jsdelivr.net/npm/chart.js'></script> <link href='https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700&family=Share+Tech+Mono&display=swap' rel='stylesheet'> <style> :root { --bg: #050505; --acid: #ccff00; --purple: #7a00ff; --panel: #111; --danger: #ff003c; } 
body { 
    background-color: var(--bg); 
    color: #ccc; 
    font-family: 'Share Tech Mono', monospace; 
    margin: 0; 
    padding: 40px; 
    background-image: radial-gradient(circle at 80% 20%, #1a1a1a 0%, #000 60%);
    position: relative;
} 

body::before {
    content: '';
    position: fixed;
    top: 0; left: 0;
    width: 100%; height: 100%;
    background: radial-gradient(circle at 80% 20%, rgba(26, 26, 26, 0.5) 0%, rgba(0, 0, 0, 0) 60%);
    animation: bgPulse 10s ease-in-out infinite;
    z-index: -1;
    pointer-events: none;
}

@keyframes bgPulse {
    0%, 100% { opacity: 0.5; }
    50% { opacity: 1; }
}

.dashboard-grid {
    position: fixed;
    top: 0; left: 0;
    width: 100%; height: 100%;
    background-image: 
        linear-gradient(rgba(204, 255, 0, 0.02) 1px, transparent 1px),
        linear-gradient(90deg, rgba(204, 255, 0, 0.02) 1px, transparent 1px);
    background-size: 50px 50px;
    animation: gridDashboard 30s linear infinite;
    z-index: -1;
    pointer-events: none;
}

@keyframes gridDashboard {
    0% { background-position: 0 0; }
    100% { background-position: 50px 50px; }
}

.dashboard-scanline {
    position: fixed;
    top: 0; left: 0;
    width: 100%; height: 100%;
    background: linear-gradient(transparent 0%, rgba(204, 255, 0, 0.02) 50%, transparent 100%);
    background-size: 100% 3px;
    animation: scanDashboard 10s linear infinite;
    z-index: -1;
    pointer-events: none;
}

@keyframes scanDashboard {
    0% { background-position: 0 0; }
    100% { background-position: 0 100%; }
}

.dashboard-glow {
    position: fixed;
    width: 400px; height: 400px;
    border-radius: 50%;
    background: radial-gradient(circle, rgba(122, 0, 255, 0.1) 0%, transparent 70%);
    filter: blur(60px);
    animation: glowFloat 12s ease-in-out infinite;
    z-index: -1;
    pointer-events: none;
}

@keyframes glowFloat {
    0%, 100% { top: 10%; right: 10%; }
    50% { top: 70%; right: 80%; }
}

.console-frame {
    background: var(--panel);
    border: 1px solid #333;
    position: relative;
    padding: 20px;
    box-shadow: 0 0 30px #000;
    margin-bottom: 25px;
    animation: frameAppear 0.5s ease-out;
}

@keyframes frameAppear {
    from {
        opacity: 0;
        transform: translateY(20px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.console-frame:hover {
    box-shadow: 0 0 40px rgba(0, 0, 0, 0.8), 0 0 10px rgba(204, 255, 0, 0.1);
    transition: box-shadow 0.3s;
}

h2, h3 { font-family: 'Orbitron', sans-serif; color: var(--acid); text-transform: uppercase; letter-spacing: 2px; } .top-bar { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #333; padding-bottom: 20px; margin-bottom: 30px; } 
.device-badge {
display: inline-block;
background: rgba(122, 0, 255, 0.2);
border: 1px solid var(--purple);
padding: 4px 12px;
border-radius: 3px;
font-size: 0.75em;
margin-left: 8px;
color: var(--purple);
}
.logout { background: transparent; border: 1px solid var(--purple); color: var(--purple); padding: 8px 20px; font-family: 'Orbitron'; cursor: pointer; transition: .3s; text-decoration: none; } 
.logout:hover { background: var(--purple); color: #000; box-shadow: 0 0 15px var(--purple); }

.console-frame::before { content:''; position:absolute; top:-1px; left:-1px; width:15px; height:15px; border-top:2px solid var(--acid); border-left:2px solid var(--acid); }
.console-frame::after { content:''; position:absolute; bottom:-1px; right:-1px; width:15px; height:15px; border-bottom:2px solid var(--acid); border-right:2px solid var(--acid); }

table { width: 100%; border-collapse: collapse; margin-bottom: 30px; }
th { text-align: left; color: #fff; border-bottom: 1px solid var(--acid); padding: 10px; font-family: 'Orbitron'; font-size: 0.9em; }
td { padding: 10px; border-bottom: 1px solid #222; color: #aaa; font-size: 0.85em; }
tr:hover td { color: var(--acid); background: rgba(204, 255, 0, 0.05); }
a { color: var(--purple); text-decoration: none; }
a:hover { color: #fff; text-decoration: underline; }

.risk-high { color: #ff003c; text-shadow: 0 0 5px red; }
.risk-med { color: #ffae00; }
.risk-low { color: var(--acid); }

.device-icon {
display: inline-block;
padding: 3px 8px;
background: rgba(204, 255, 0, 0.1);
border-radius: 3px;
font-size: 0.8em;
color: var(--acid);
}

.chart-container {
display: grid;
grid-template-columns: repeat(3, 1fr);
gap: 20px;
margin-top: 30px;
}
.chart-box {
background: #0a0a0a;
border: 1px solid #333;
padding: 15px;
}
.chart-box h4 {
color: var(--purple);
font-family: 'Orbitron';
font-size: 0.85em;
margin: 0 0 15px 0;
text-align: center;
}
canvas { background: transparent; width: 100% !important; height: 200px !important; }

.blacklist-form {
background: rgba(255, 0, 60, 0.05);
border: 1px solid var(--danger);
padding: 20px;
margin-top: 20px;
}
.blacklist-form input[type="text"] {
background: rgba(0,0,0,0.5);
border: 1px solid #333;
border-bottom: 2px solid var(--danger);
padding: 10px;
color: #fff;
width: 200px;
margin-right: 10px;
font-family: 'Share Tech Mono';
}
.blacklist-form input[type="text"]:focus {
outline: none;
border-bottom-color: var(--acid);
}
.btn-block {
background: var(--danger);
color: #fff;
border: none;
padding: 10px 20px;
font-family: 'Orbitron';
cursor: pointer;
transition: .3s;
font-weight: bold;
}
.btn-block:hover {
background: #fff;
color: var(--danger);
box-shadow: 0 0 20px var(--danger);
}
.btn-unblock {
background: transparent;
color: var(--acid);
border: 1px solid var(--acid);
padding: 5px 15px;
font-family: 'Orbitron';
cursor: pointer;
transition: .3s;
font-size: 0.8em;
}
.btn-unblock:hover {
background: var(--acid);
color: #000;
}
.blocked-ip {
background: rgba(255, 0, 60, 0.1);
border-left: 3px solid var(--danger);
}
.success-badge {
background: rgba(204, 255, 0, 0.3);
color: var(--acid);
padding: 3px 8px;
border-radius: 3px;
font-size: 0.8em;
}
.failed-badge {
background: rgba(255, 0, 60, 0.3);
color: var(--danger);
padding: 3px 8px;
border-radius: 3px;
font-size: 0.8em;
}
</style></head>

<body>
<div class='dashboard-grid'></div>
<div class='dashboard-scanline'></div>
<div class='dashboard-glow'></div>

<div class='top-bar'> 
    <div> 
        <h2 style='margin:0'>🔐 SECURITY COMMAND CENTER</h2> 
        <span style='color:#666; font-size:0.8em'>SESSION IP: <span style='color:var(--acid)'>{{ip}}</span></span>
        <span class='device-badge'>{{device_type}}</span>
        <span class='device-badge'>{{browser}}</span>
        <span class='device-badge'>{{os_name}}</span>
    </div> 
    <a href='/logout' class='logout'>TERMINATE SESSION</a>
</div>

<div class='console-frame'> 
    <h3 style='border-left: 3px solid var(--danger); padding-left: 10px;'>🚫 IP BLACKLIST MANAGEMENT</h3> 
    
    <div class='blacklist-form'>
        <h4 style='color: var(--danger); margin: 0 0 15px 0; font-family: Orbitron;'>Block New IP Address</h4>
        <form id='blockForm' onsubmit='blockIP(event)'>
            <input type='text' id='blockIP' name='ip' placeholder='192.168.1.100' pattern='^(\d{1,3}\.){3}\d{1,3}$' required>
            <input type='text' id='blockReason' name='reason' placeholder='Reason for blocking' style='width:300px;' required>
            <button type='submit' class='btn-block'>⚠️ BLOCK IP</button>
        </form>
        <p id='blockMessage' style='margin-top:10px; color:var(--acid);'></p>
    </div>
    
    <table style='margin-top: 30px;'> 
        <tr><th>IP ADDRESS</th><th>REASON</th><th>BLOCKED BY</th><th>BLOCKED AT</th><th>STATUS</th><th>ACTION</th></tr> 
        {% for b in blacklist %} 
        <tr class='{% if b[5] %}blocked-ip{% endif %}'> 
            <td style='color: var(--danger); font-weight: bold;'>{{b[1]}}</td> 
            <td>{{b[2]}}</td> 
            <td>{{b[3]}}</td> 
            <td>{{b[4]}}</td> 
            <td>{% if b[5] %}<span style='color:var(--danger);'>🔴 ACTIVE</span>{% else %}<span style='color:#666;'>⚪ INACTIVE</span>{% endif %}</td> 
            <td>
                {% if b[5] %}
                <button class='btn-unblock' onclick='unblockIP("{{b[1]}}")'>UNBLOCK</button>
                {% else %}
                <span style='color:#666; font-size:0.8em;'>Removed</span>
                {% endif %}
            </td> 
        </tr> 
        {% endfor %} 
    </table>
</div>

<div class='console-frame'>
    <h3 style='border-left: 3px solid #ffae00; padding-left: 10px;'>🔑 LOGIN ATTEMPTS MONITOR</h3>
    <table>
        <tr><th>IP ADDRESS</th><th>STATUS</th><th>TIMESTAMP</th></tr>
        {% for attempt in login_attempts %}
        <tr>
            <td>{{attempt[0]}}</td>
            <td>
                {% if attempt[1] %}
                <span class='success-badge'>✓ SUCCESS</span>
                {% else %}
                <span class='failed-badge'>✗ FAILED</span>
                {% endif %}
            </td>
            <td>{{attempt[2]}}</td>
        </tr>
        {% endfor %}
    </table>
</div>

<div class='console-frame'> 
    <h3 style='border-left: 3px solid var(--purple); padding-left: 10px;'>Live Logs [DEVICE TRACKING ACTIVE]</h3> 
    <table> 
        <tr><th>ID</th><th>USER</th><th>ROLE</th><th>ACTION</th><th>TIME</th><th>SOURCE</th><th>DEVICE</th><th>BROWSER</th><th>OS</th></tr> 
        {% for r in logs %} 
        <tr> 
            <td><a href='/log/{{r[0]}}'>#{{r[0]}}</a></td> 
            <td>{{r[1]}}</td> 
            <td style='color:#fff'>{{r[2]}}</td> 
            <td>{{r[3]}}</td> 
            <td>{{r[4]}}</td> 
            <td>{{r[5]}}</td> 
            <td><span class='device-icon'>{{r[8]}}</span></td> 
            <td>{{r[6]}}</td> 
            <td>{{r[7]}}</td> 
        </tr> 
        {% endfor %} 
    </table>

    <h3 style='border-left: 3px solid #ff003c; padding-left: 10px; margin-top: 40px;'>Threat Detection [AI-ENHANCED]</h3>
    <table>
        <tr><th>ALERT ID</th><th>REF LOG</th><th>USER</th><th>ACTION</th><th>DEVICE</th><th>RISK LEVEL</th></tr>
        {% for a in alerts %}
        <tr>
            <td>{{a[0]}}</td>
            <td><a href='/log/{{a[1]}}'>{{a[1]}}</a></td>
            <td>{{a[2]}}</td>
            <td>{{a[3]}}</td>
            <td><span class='device-icon'>{{a[10]}}</span> {{a[8]}}</td>
            <td class='{% if a[7]=="High Risk" %}risk-high{% elif a[7]=="Medium Risk" %}risk-med{% else %}risk-low{% endif %}'>
                {{a[7]}} ({{ "%.0f"|format(a[6]) }}%)
            </td>
        </tr>
        {% endfor %}
    </table>
</div>

<div class='console-frame'>
    <h3>Device Intelligence Dashboard</h3>
    <div class='chart-container'>
        <div class='chart-box'>
            <h4>⚡ IP DISTRIBUTION</h4>
            <canvas id='chartIP'></canvas>
        </div>
        <div class='chart-box'>
            <h4>💻 DEVICE TYPES</h4>
            <canvas id='chartDevice'></canvas>
        </div>
        <div class='chart-box'>
            <h4>🌐 BROWSERS</h4>
            <canvas id='chartBrowser'></canvas>
        </div>
    </div>
    <div class='chart-container' style='margin-top: 20px;'>
        <div class='chart-box' style='grid-column: 1 / -1;'>
            <h4>🖥️ OPERATING SYSTEMS</h4>
            <canvas id='chartOS' style='height: 150px !important;'></canvas>
        </div>
    </div>
</div>

<script>
function blockIP(event) {
    event.preventDefault();
    const ip = document.getElementById('blockIP').value;
    const reason = document.getElementById('blockReason').value;
    
    fetch('/api/blacklist/add', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: `ip=${ip}&reason=${encodeURIComponent(reason)}`
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('blockMessage').textContent = data.message;
        if(data.success) {
            setTimeout(() => location.reload(), 1500);
        }
    });
    
    return false;
}

function unblockIP(ip) {
    if(!confirm(`Unblock IP ${ip}?`)) return;
    
    fetch('/api/blacklist/remove', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: `ip=${ip}`
    })
    .then(response => response.json())
    .then(data => {
        alert(data.message);
        if(data.success) location.reload();
    });
}

const ipData = {{ip_counts|tojson}};
const deviceData = {{devices|tojson}};
const browserData = {{browsers|tojson}};
const osData = {{os_stats|tojson}};

const chartConfig = {
    plugins: {
        legend: {
            labels: {
                color: '#fff',
                font: { family: 'Share Tech Mono', size: 10 }
            }
        }
    },
    scales: {
        x: { ticks: { color: '#666', font: { size: 9 } }, grid: { color: '#222' } },
        y: { ticks: { color: '#666', font: { size: 9 } }, grid: { color: '#222' }, beginAtZero: true }
    }
};

new Chart(document.getElementById('chartIP'), {
    type: 'bar',
    data: {
        labels: Object.keys(ipData),
        datasets: [{
            label: 'Requests',
            data: Object.values(ipData),
            backgroundColor: 'rgba(204, 255, 0, 0.3)',
            borderColor: '#ccff00',
            borderWidth: 1
        }]
    },
    options: chartConfig
});

new Chart(document.getElementById('chartDevice'), {
    type: 'doughnut',
    data: {
        labels: Object.keys(deviceData),
        datasets: [{
            data: Object.values(deviceData),
            backgroundColor: ['rgba(122, 0, 255, 0.6)', 'rgba(204, 255, 0, 0.6)', 'rgba(255, 0, 60, 0.6)'],
            borderColor: ['#7a00ff', '#ccff00', '#ff003c'],
            borderWidth: 2
        }]
    },
    options: {
        plugins: {
            legend: {
                labels: { color: '#fff', font: { family: 'Share Tech Mono', size: 10 } }
            }
        }
    }
});

new Chart(document.getElementById('chartBrowser'), {
    type: 'pie',
    data: {
        labels: Object.keys(browserData),
        datasets: [{
            data: Object.values(browserData),
            backgroundColor: [
                'rgba(204, 255, 0, 0.5)',
                'rgba(122, 0, 255, 0.5)',
                'rgba(255, 174, 0, 0.5)',
                'rgba(0, 255, 204, 0.5)',
                'rgba(255, 0, 60, 0.5)'
            ],
            borderWidth: 1
        }]
    },
    options: {
        plugins: {
            legend: {
                labels: { color: '#fff', font: { family: 'Share Tech Mono', size: 10 } }
            }
        }
    }
});

new Chart(document.getElementById('chartOS'), {
    type: 'bar',
    data: {
        labels: Object.keys(osData),
        datasets: [{
            label: 'Count',
            data: Object.values(osData),
            backgroundColor: 'rgba(122, 0, 255, 0.4)',
            borderColor: '#7a00ff',
            borderWidth: 2
        }]
    },
    options: {
        indexAxis: 'y',
        plugins: {
            legend: {
                labels: { color: '#fff', font: { family: 'Share Tech Mono', size: 10 } }
            }
        },
        scales: {
            x: { ticks: { color: '#666' }, grid: { color: '#222' }, beginAtZero: true },
            y: { ticks: { color: '#666', font: { size: 9 } }, grid: { color: '#222' } }
        }
    }
});
</script>
</body></html>"""

LOG_DETAIL_HTML = """<!DOCTYPE html>
<html lang='en'><head><meta charset='UTF-8'><title>INSANE // LOG DETAIL</title> <link href='https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700&family=Share+Tech+Mono&display=swap' rel='stylesheet'> <style> :root { --bg: #050505; --acid: #ccff00; --purple: #7a00ff; --panel: #111; } 
body { 
    background-color: var(--bg); 
    color: #ccc; 
    font-family: 'Share Tech Mono', monospace; 
    margin: 0; 
    padding: 40px; 
    background-image: radial-gradient(circle at 80% 20%, #1a1a1a 0%, #000 60%);
    position: relative;
} 

body::before {
    content: '';
    position: fixed;
    top: 0; left: 0;
    width: 100%; height: 100%;
    background: radial-gradient(circle at 50% 50%, rgba(26, 26, 26, 0.3) 0%, rgba(0, 0, 0, 0) 70%);
    animation: detailPulse 8s ease-in-out infinite;
    z-index: -1;
}

@keyframes detailPulse {
    0%, 100% { opacity: 0.5; transform: scale(1); }
    50% { opacity: 1; transform: scale(1.05); }
}

h2, h3 { font-family: 'Orbitron', sans-serif; color: var(--acid); text-transform: uppercase; letter-spacing: 2px; } .console-frame { background: var(--panel); border: 1px solid #333; position: relative; padding: 25px; box-shadow: 0 0 30px #000; margin-bottom: 20px; } .console-frame::before { content:''; position:absolute; top:-1px; left:-1px; width:20px; height:20px; border-top:2px solid var(--acid); border-left:2px solid var(--acid); } .console-frame::after { content:''; position:absolute; bottom:-1px; right:-1px; width:20px; height:20px; border-bottom:2px solid var(--acid); border-right:2px solid var(--acid); }
.detail-grid {
display: grid;
grid-template-columns: 200px 1fr;
gap: 15px;
margin: 20px 0;
animation: slideIn 0.5s ease-out;
}

@keyframes slideIn {
    from {
        opacity: 0;
        transform: translateX(-20px);
    }
    to {
        opacity: 1;
        transform: translateX(0);
    }
}

.detail-label {
color: var(--purple);
font-family: 'Orbitron';
font-size: 0.85em;
}
.detail-value {
color: #fff;
padding: 8px 12px;
background: rgba(204, 255, 0, 0.05);
border-left: 2px solid var(--acid);
}
.device-section {
background: rgba(122, 0, 255, 0.1);
border: 1px solid var(--purple);
padding: 15px;
margin: 20px 0;
animation: deviceAppear 0.6s ease-out 0.2s both;
}

@keyframes deviceAppear {
    from {
        opacity: 0;
        transform: scale(0.95);
    }
    to {
        opacity: 1;
        transform: scale(1);
    }
}

.device-section h4 {
color: var(--purple);
font-family: 'Orbitron';
margin: 0 0 15px 0;
}
table { width: 100%; border-collapse: collapse; margin-top: 20px; } th { text-align: left; color: #fff; border-bottom: 1px solid var(--acid); padding: 10px; font-family: 'Orbitron'; font-size: 0.9em; } td { padding: 10px; border-bottom: 1px solid #222; color: #aaa; } .risk-high { color: #ff003c; text-shadow: 0 0 5px red; } .risk-med { color: #ffae00; } .risk-low { color: var(--acid); } 
.back-btn { 
    background: transparent; 
    border: 1px solid var(--acid); 
    color: var(--acid); 
    padding: 10px 25px; 
    font-family: 'Orbitron'; 
    cursor: pointer; 
    transition: .3s; 
    text-decoration: none; 
    display: inline-block;
    position: relative;
    overflow: hidden;
} 

.back-btn::before {
    content: '';
    position: absolute;
    top: 50%; left: -100%;
    width: 100%; height: 100%;
    background: rgba(204, 255, 0, 0.2);
    transform: translateY(-50%);
    transition: 0.3s;
}

.back-btn:hover::before {
    left: 100%;
}

.back-btn:hover { 
    background: var(--acid); 
    color: #000; 
    box-shadow: 0 0 15px var(--acid); 
} 
</style></head>

<body><div class='console-frame'> <h2 style='border-left: 3px solid var(--purple); padding-left: 10px;'>LOG DETAIL // #{{log[0]}}</h2> {% if log %} <div class='detail-grid'> <div class='detail-label'>LOG ID:</div> <div class='detail-value'>{{log[0]}}</div> <div class='detail-label'>USER:</div> <div class='detail-value'>{{log[1]}} ({{log[2]}})</div> <div class='detail-label'>ACTION TYPE:</div> <div class='detail-value'>{{log[3]}}</div> <div class='detail-label'>TIMESTAMP:</div> <div class='detail-value'>{{log[4]}}</div> <div class='detail-label'>IP ADDRESS:</div> <div class='detail-value'>{{log[5]}}</div> </div>
    
    <div class='device-section'>
        <h4>🔍 DEVICE INTELLIGENCE</h4>
        <div class='detail-grid'>
            <div class='detail-label'>BROWSER:</div>
            <div class='detail-value'>{{log[6]}}</div>
            <div class='detail-label'>OPERATING SYSTEM:</div>
            <div class='detail-value'>{{log[7]}}</div>
            <div class='detail-label'>DEVICE TYPE:</div>
            <div class='detail-value'>{{log[8]}}</div>
        </div>
    </div>
    
    {% if alerts %}
    <h3 style='margin-top: 30px; color: #ff003c;'>⚠️ RELATED ALERTS</h3>
    <table>
        <tr><th>ALERT ID</th><th>RISK SCORE</th><th>THREAT TYPE</th></tr>
        {% for a in alerts %}
        <tr>
            <td>{{a[0]}}</td>
            <td>{{ "%.2f"|format(a[1]) }}%</td>
            <td class='{% if a[2]=="High Risk" %}risk-high{% elif a[2]=="Medium Risk" %}risk-med{% else %}risk-low{% endif %}'>{{a[2]}}</td>
        </tr>
        {% endfor %}
    </table>
    {% else %}
    <p style='color: var(--acid); margin-top: 20px;'>✓ No alerts associated with this log.</p>
    {% endif %}
    
    {% else %}
    <p style='color: #ff003c;'>❌ Log not found.</p>
    {% endif %}
    
    <div style='margin-top: 30px;'>
        <a href='/dashboard' class='back-btn'>← BACK TO DASHBOARD</a>
    </div>
</div></body></html>"""

# ==========================================================
# RUN APPLICATION
# ==========================================================
if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════╗
║  🔐 INSANE SECURITY SYSTEM -                                ║
║                                                              ║
║  ⚠️  DEVELOPMENT MODE: {'ENABLED ' if DEVELOPMENT_MODE else 'DISABLED'}                         ║
║  ✅ Password Hashing (bcrypt)                               ║
║  ✅ Rate Limiting (20 login attempts/min)                   ║
║  ✅ IP Blacklist System                                     ║
║  ✅ Login Attempt Tracking                                  ║
║  ✅ Device Intelligence                                     ║
║  ✅ AI Threat Detection                                     ║
║  🎨 Animated CSS Backgrounds                                ║
║                                                             ║
║  📌 Default Password: admin123                              ║
║  📌 MySQL Password: admin123 (change in code if needed)   ║
║  📌 Running on: http://127.0.0.1:5000                       ║
║  📌 Emergency Unblock: http://127.0.0.1:5000/emergency/unblock║
║                                                              ║
║  Made by: Hammad Naeem                                       ║
╚══════════════════════════════════════════════════════════════╝
    """)
    app.run(debug=True, host="0.0.0.0", port=5000)