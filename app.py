y
# ================= IMPORTS =================
from datetime import datetime, timedelta
from flask import Flask, render_template, request, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import requests
import time
import random

# ================= GLOBAL STORAGE =================
risk_score = {}
risk_reasons = {}
attack_history = {}
blocked_ips = {}
login_attempts = {}
ip_tracker = {}
BOT_TOKEN = "8852909328:AAHje93eBthZ2_4B9ojfA_cBNuKQCiksIho"
CHAT_ID = "5934910421"
trusted_ips = [
    "127.0.0.1"
]
ip_behavior = {}
rate_limit_data = {}
captcha_store = {}
# ================= ATTACK PATTERNS =================
attack_patterns = {
    "SQL Injection": [
        "' OR 1=1",
        "--",
        "UNION SELECT",
        "DROP TABLE"
    ],

    "XSS": [
        "<script>",
        "alert(",
        "</script>"
    ],

    "Command Injection": [
        ";",
        "&&",
        "|",
        "whoami"
    ],

    "Path Traversal": [
        "../",
        "/etc/passwd"
    ]
}

# ================= RISK ENGINE =================
def calculate_risk(ip, action):
    if ip not in risk_score:
        risk_score[ip] = 0

    if action == "fail":
        risk_score[ip] += 20

    elif action == "success":
        risk_score[ip] = max(0, risk_score[ip] - 10)

    elif action == "block":
        risk_score[ip] = 100

    if risk_score[ip] >= 80:
        return "CRITICAL", risk_score[ip]
    elif risk_score[ip] >= 50:
        return "HIGH", risk_score[ip]
    elif risk_score[ip] >= 20:
        return "MEDIUM", risk_score[ip]
    else:
        return "LOW", risk_score[ip]



# ================= RISK INTELLIGENCE ENGINE =================
def update_risk(ip, points, reason):

    if ip not in risk_score:
        risk_score[ip] = 0

    if ip not in risk_reasons:
        risk_reasons[ip] = []

    risk_score[ip] += points

    # avoid duplicate reasons
    if reason not in risk_reasons[ip]:
        risk_reasons[ip].append(reason)

    # max score = 100
    if risk_score[ip] > 100:
        risk_score[ip] = 100
# ================= TELEGRAM ALERT =================
def send_telegram_alert(message):
    print("Sending Telegram:", message)

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

    data = {
        "chat_id": CHAT_ID,
        "text": message
    }

    try:
        requests.post(url, data=data)

    except:
        print("Telegram alert failed")


# ================= FLASK INIT =================
app = Flask(__name__)

#=================captcha===========
def generate_captcha(ip):

    a = random.randint(1, 9)
    b = random.randint(1, 9)

    captcha_store[ip] = {
        "question": f"{a} + {b}",
        "answer": str(a + b)
    }

    return captcha_store[ip]["question"]

#-----------login middleware
def login_required(route_function):

    def wrapper(*args, **kwargs):

        if "user" not in session:
            flash("Login required")
            return redirect(url_for("login"))

        return route_function(*args, **kwargs)

    wrapper.__name__ = route_function.__name__

    return wrapper

#-----------admin middleware
def admin_required(route_function):

    def wrapper(*args, **kwargs):

        if not session.get("admin"):
            flash("Admin access required")
            return redirect(url_for("admin_login"))

        return route_function(*args, **kwargs)

    wrapper.__name__ = route_function.__name__

    return wrapper

app.secret_key = "securelogin_key_123"
app.permanent_session_lifetime = timedelta(minutes=2)
# ================= SESSION SECURITY =================
app.permanent_session_lifetime = timedelta(minutes=2)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)

# ================= DATABASE MODELS =================
class User(db.Model):

    lock_time = db.Column(db.DateTime, nullable=True)
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(100), unique=True, nullable=False)

    email = db.Column(db.String(100), unique=True, nullable=False)

    password = db.Column(db.String(200), nullable=False)

    failed_attempts = db.Column(db.Integer, default=0)
    is_locked = db.Column(db.Boolean, default=False)

class LoginLog(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    status = db.Column(db.String(20))  # success / fail
    message = db.Column(db.String(200))

    entered_password = db.Column(db.String(200))
    ip_address = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.now)


# ================= ATTACK DETECTION =================
def detect_attack(text):
    text = text.lower()

    for attack_type, patterns in attack_patterns.items():
        for pattern in patterns:
            if pattern.lower() in text:
                return attack_type

    return None

# ================= RATE LIMIT FUNCTION =================
def check_rate_limit(ip):

    now = time.time()

    if ip not in rate_limit_data:

        rate_limit_data[ip] = {
            "requests": [],
            "blocked_until": None
        }

    # ---------------- BLOCK CHECK ----------------

    blocked_until = rate_limit_data[ip]["blocked_until"]

    if blocked_until:

        if now < blocked_until:
            return False

        else:
            rate_limit_data[ip]["blocked_until"] = None

    # ---------------- STORE REQUEST ----------------

    rate_limit_data[ip]["requests"].append(now)

    # keep only last 60 seconds
    rate_limit_data[ip]["requests"] = [

        t for t in rate_limit_data[ip]["requests"]

        if now - t < 60
    ]

    request_count = len(rate_limit_data[ip]["requests"])

    # ---------------- WARNING LEVEL ----------------

    if request_count >= 15:

        update_risk(ip, 30, "High request rate")

    # ---------------- BLOCK LEVEL ----------------

    if request_count >= 25:

        rate_limit_data[ip]["blocked_until"] = now + 120

        send_telegram_alert(
            f"🚨 RATE LIMIT TRIGGERED\n\n"
            f"IP: {ip}\n"
            f"Requests: {request_count}/minute"
        )

        return False

    return True

# ================= LOGIN ROUTE =================
@app.route('/', methods=['GET', 'POST'])
def login():

    ip = request.remote_addr

    if ip in blocked_ips:
        block_data = blocked_ips[ip]
        block_time = block_data["time"]
        duration = block_data["duration"]

        # still blocked
        if datetime.now() - block_time < timedelta(minutes=duration):
            send_telegram_alert(f"🚫 BLOCKED IP VISIT ATTEMPT\nIP: {ip}")
            return render_template("blocked.html"), 403

        # auto unblock after time ends
        else:
            blocked_ips.pop(ip, None)

    if ip not in ip_behavior:
        ip_behavior[ip] = {
            "requests": [],
            "fail_count": 0
        }

    now = time.time()

    ip_behavior[ip]["requests"].append(now)

    # keep last 60 seconds only
    ip_behavior[ip]["requests"] = [
        t for t in ip_behavior[ip]["requests"]
        if now - t < 60
    ]

# ---------------- ANOMALY DETECTION ----------------
    if len(ip_behavior[ip]["requests"]) > 10:
        update_risk(ip, 50, "High request rate anomaly")
        send_telegram_alert(
            f"🚨 ANOMALY DETECTED\nIP: {ip}\nReason: High request rate"
        )

        flash("Too many login attempts. Try again later.")
        generate_captcha(ip)
        return render_template(
            'login.html',
            captcha=captcha_store.get(ip, {}).get("question")
        )

    if ip in trusted_ips:
        update_risk(ip, 0, "Trusted IP - monitoring only")

    if ip not in risk_score:
        risk_score[ip] = 0
    # check if IP is blocked
    if ip in blocked_ips:
        block_time = blocked_ips[ip]["time"]
        duration = blocked_ips[ip]["duration"]

        risk_level, score = calculate_risk(ip, "block")

        if datetime.now() - block_time < timedelta(minutes=duration):
            flash("Too many login attempts. Try again later.")
            generate_captcha(ip)
            return render_template(
                'login.html',
                captcha=captcha_store.get(ip, {}).get("question")
            )
        else:
            blocked_ips.pop(ip, None)

    if request.method == 'POST':

        user_answer = request.form.get("captcha_answer")

        if ip in captcha_store and request.method == 'POST':


            correct = captcha_store[ip]["answer"]

            # only check CAPTCHA if user entered something
            if user_answer and user_answer != correct:

                update_risk(ip, 30, "CAPTCHA failed")

                flash("Wrong CAPTCHA")

                generate_captcha(ip)

                return render_template(
                    "login.html",
                     captcha=captcha_store[ip]["question"]
                )



        username = request.form['username']

        password = request.form['password']
       # ---------- ATTACK CHECK ----------
        payload = f"{username} {password}"
        attack = detect_attack(f"{username} {password}")

        # always ensure storage exists
        if ip not in attack_history:
            attack_history[ip] = []

        # store attack immediately
        if attack:
            attack_history[ip].append({
                "type": attack,
                "time": datetime.now().strftime("%H:%M:%S")
            })

            update_risk(ip, 40, attack)

            send_telegram_alert(
                f"🚨 ATTACK DETECTED\nType: {attack}\nUser: {username}\nIP: {ip}"
            )

            # increase risk properly
            update_risk(ip, 40, attack)

            send_telegram_alert(
                f"🚨 ATTACK DETECTED\n\n"
                f"Type: {attack}\n"
                f"User: {username}\n"
                f"IP: {ip}"
            )



        # ---------- USER TRACK ----------

        # RATE LIMIT CHECK
        if not check_rate_limit(ip):

            flash("Too many requests. Slow down.")

            generate_captcha(ip)
            return render_template(
                "login.html",
                captcha=captcha_store.get(ip, {}).get("question")
            )

        if ip not in ip_tracker:
            ip_tracker[ip] = {
                "fail": 0,
                "success": 0,
                "first_seen": datetime.now()
            }

        user = User.query.filter_by(username=username).first()
        # HARD BLOCK CHECK (IMPORTANT FIX)

        # ---------- LOCK CHECK ----------
        if user and user.is_locked:
            if user.lock_time and datetime.now() - user.lock_time > timedelta(minutes=5):
                user.is_locked = False
                user.failed_attempts = 0
                user.lock_time = None
                db.session.commit()
            else:
                flash("Try again later")
            generate_captcha(ip)
            return render_template(
                'login.html',
                captcha=captcha_store.get(ip, {}).get("question")
            )

        if user:

            if user and user.is_locked:
                flash("Account locked due to suspicious activity")
                generate_captcha(ip)
                return render_template(
                    'login.html',
                    captcha=captcha_store.get(ip, {}).get("question")
                )

            # ---------- SUCCESS ----------
            if bcrypt.checkpw(
                password.encode('utf-8'),
                user.password.encode('utf-8'),
            ):
                ip_tracker[ip]["success"] += 1
                # ✅ SUCCESS LOG
                log = LoginLog(username=username,status="success",message="Login successful",entered_password=password,ip_address=ip)
                db.session.add(log)

                # reset counter on success
                user.failed_attempts = 0
                update_risk(ip, -10, "Login success reward")
                user.is_locked = False
                if ip in login_attempts:
                    login_attempts[ip] = []

                db.session.commit()

                session.permanent = True
                session['user'] = username
                return redirect(url_for('dashboard'))


            # ---------- FAIL ----------

            else:

                # ❌ FAIL LOG
                log = LoginLog(username=username, status="fail",message="Wrong password attempt",entered_password=password,ip_address=ip)
                db.session.add(log)

                # increase failed attempts
                user.failed_attempts += 1
                update_risk(ip, 20, f"Failed login attempt ({ip_tracker[ip]['fail']})")
                ip_tracker[ip]["fail"] += 1
                # brute force detection
                if user.failed_attempts >= 3:
                    update_risk(ip, 60, "Brute force attack")
                    user.is_locked = True
                    user.lock_time = datetime.now()

                    blocked_ips[ip] = {
                        "reason": "Brute force detected",
                        "time": datetime.now(),
                        "duration": 5  # minutes
                    }

                    send_telegram_alert(
                        f"🚨 BRUTE FORCE DETECTED\n\n"
                        f"User: {username}\n"
                        f"IP: {ip}\n"
                        f"Risk: CRITICAL\n"
                        f"Risk Score: {risk_score[ip]}\n"
                        f"Reasons: {risk_reasons[ip]}"
                    )


                # AUTO UNBLOCK CHECK
                if ip in blocked_ips:
                    block_time = blocked_ips[ip]["time"]
                    duration = blocked_ips[ip]["duration"]

                    if datetime.now() - block_time > timedelta(minutes=duration):
                        del blocked_ips[ip]

                now = time.time()

                # initialize if not exists
                if ip not in login_attempts:
                    login_attempts[ip] = []

                # store attempt time
                login_attempts[ip].append(now)

                # keep only last 60 seconds
                login_attempts[ip] = [
                    t for t in login_attempts[ip]
                    if now - t < 60
                ]

                if len(login_attempts[ip]) >= 3:
                    user.is_locked = True
                    flash("Too many login attempts")

                db.session.commit()


                flash("Invalid password")
                generate_captcha(ip)
                return render_template(
                    'login.html',
                    captcha=captcha_store.get(ip, {}).get("question")
                )

        else:

            flash("User Not Found")
            generate_captcha(ip)
            return render_template(
                'login.html',
                captcha=captcha_store.get(ip, {}).get("question")
            )

        # ================= FINAL GET FALLBACK =================
    captcha = generate_captcha(ip)
    return render_template('login.html', captcha=captcha)

# ================= OTHER ROUTES =================
@app.route('/dashboard')
@login_required
def dashboard():

    logs = LoginLog.query.order_by(
        LoginLog.timestamp.desc()
    ).limit(10).all()

    return render_template(
        "dashboard.html",
        logs=logs,
        ip_tracker=ip_tracker,
        blocked_ips=blocked_ips,
        risk_score=risk_score,
        attack_history=attack_history,
        risk_reasons=risk_reasons
)

@app.route('/signup', methods=['GET', 'POST'])
def signup():

    if request.method == 'POST':

        username = request.form['username']

        email = request.form['email']

        password = request.form['password']

        # CHECK EXISTING USERNAME
        existing_user = User.query.filter_by(username=username).first()

        # CHECK EXISTING EMAIL
        existing_email = User.query.filter_by(email=email).first()

        if existing_user:
            flash("Username already exists")
            return render_template('signup.html')

        if existing_email:
            flash("Email already exists")
            return render_template('signup.html')

        # PASSWORD HASHING

        hashed_password = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

        new_user = User(
            username=username,
            email=email,
            password=hashed_password
        )

        db.session.add(new_user)

        db.session.commit()

        flash("Account Created Successfully")
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/logs')
@login_required
def logs():
    all_logs = LoginLog.query.order_by(LoginLog.timestamp.desc()).all()
    return render_template("logs.html", logs=all_logs)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))


@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == "admin" and password == "admin123":
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid admin credentials")

    return render_template('admin_login.html')


# ================= ADMIN =================
@app.route('/admin-dashboard')
@admin_required
def admin_dashboard():
    if not session.get('admin'):
        return redirect(url_for('admin_login'))

    logs = LoginLog.query.order_by(LoginLog.timestamp.desc()).limit(10).all()

    return render_template(
        "dashboard.html",
        logs=logs,
        ip_tracker=ip_tracker,
        blocked_ips=blocked_ips,
        risk_score=risk_score,
        risk_reasons=risk_reasons,
        attack_history=attack_history

    )


@app.route('/ip-stats')
def ip_stats():
    return ip_tracker

@app.route('/blocked-ips')
@admin_required
def show_blocked():
    return blocked_ips

@app.route('/block-ip', methods=['POST'])
@admin_required
def block_ip():
    ip = request.form['ip']

    blocked_ips[ip] = {
        "reason": "Manual admin block",
        "time": datetime.now(),
        "duration": 99999
    }

    flash(f"IP {ip} blocked successfully")
    return redirect(url_for('admin_dashboard'))


@app.route('/unblock-ip', methods=['POST'])
@admin_required
def unblock_ip():

    ip = request.form['ip']

    if ip in blocked_ips:
        del blocked_ips[ip]

    flash(f"{ip} unblocked")

    return redirect(url_for('admin_dashboard'))
# ================= RUN =================
if __name__ == '__main__':

    with app.app_context():
        db.create_all()

    app.run(host='0.0.0.0', port=5000, debug=True)
                                                          
