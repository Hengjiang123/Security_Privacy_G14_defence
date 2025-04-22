from flask import Flask, render_template, request, redirect, url_for, session, flash
from collections import deque
import time, json
from models import db, User, Transaction
from passlib.hash import pbkdf2_sha256
from datetime import datetime, timedelta
import pyotp, qrcode, base64, io
from config import (
    SQLALCHEMY_DATABASE_URI,
    SQLALCHEMY_TRACK_MODIFICATIONS,
    SECRET_KEY
)

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = SQLALCHEMY_TRACK_MODIFICATIONS
    app.config['SECRET_KEY'] = SECRET_KEY

    db.init_app(app)

    return app

IP_DEFENCE_FILE = 'ip_defence.json'

def load_ip_settings():
    try:
        with open(IP_DEFENCE_FILE, 'r') as f:
            data = json.load(f)
            limit = int(data.get('rate_limit', 60))
            blacklist = set(data.get('blacklist', []))
            return limit, blacklist
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        return 60, set()

def save_ip_settings(limit, blacklist):
    with open(IP_DEFENCE_FILE, 'w') as f:
        json.dump({'rate_limit': limit, 'blacklist': list(blacklist)}, f)

# Load initial settings
RATE_LIMIT_PER_MIN, BLACKLIST = load_ip_settings()
ADMIN_WHITELIST = {'127.0.0.1', '192.168.1.69'}
ip_requests = {}  # Dictionary to track requests per IP

app = create_app()

@app.before_request
def rate_limiter():
    ip = request.remote_addr or 'unknown'

    if ip in ADMIN_WHITELIST:
        return

    # check if the IP is in the blacklist
    if ip in BLACKLIST:
        return "Your IP has been blocked due to too many requests.", 429

    # record the request time
    now = time.time()
    dq = ip_requests.setdefault(ip, deque())
    dq.append(now)

    # remove requests older than 60 seconds
    while dq and now - dq[0] > 60:
        dq.popleft()

    # check if the rate limit is exceeded
    if len(dq) > RATE_LIMIT_PER_MIN:
        BLACKLIST.add(ip)
        save_ip_settings(RATE_LIMIT_PER_MIN, BLACKLIST)
        return "Too many requests from your IP. You are temporarily blocked.", 429
    
@app.after_request
def set_security_headers(response):
    response.headers['Server'] = 'SecureBank'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response   

@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        account_no = request.form.get('account_no')
        username = request.form.get('username')
        password = request.form.get('password')

        existing_user = User.query.filter_by(account_no=account_no).first()
        if existing_user:
            flash("This account number is already registered.")
            return redirect(url_for('register'))

        password_hash = pbkdf2_sha256.hash(password)

        enable_2fa = request.form.get('enable_2fa') == 'on'
        totp_secret = pyotp.random_base32() if enable_2fa else None

        new_user = User(
            account_no=account_no,
            username=username,
            password_hash=password_hash,
            totp_secret=totp_secret
        )
        db.session.add(new_user)
        db.session.commit()

        if enable_2fa:
            # LET USER SETUP 2FA
            session['pre_2fa_user_id'] = new_user.id
            return redirect(url_for('setup_2fa', user_id=new_user.id))

        flash("Registration successful! You can now log in.")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/setup-2fa/<int:user_id>')
def setup_2fa(user_id):
    user = User.query.get_or_404(user_id)
    if not user.totp_secret:
        flash("2FA is not enabled for this user.")
        return redirect(url_for('login'))

    totp = pyotp.TOTP(user.totp_secret)
    uri = totp.provisioning_uri(name=user.username, issuer_name="DigitalBank")
    img = qrcode.make(uri)

    filepath = f"static/qr.png"
    img.save(filepath)

    return render_template('setup_2fa.html', qr_path=url_for('static', filename=f"qr.png"))

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if 'pre_2fa_user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['pre_2fa_user_id'])
    totp = pyotp.TOTP(user.totp_secret)

    if request.method == 'POST':
        token = request.form.get('token')
        if totp.verify(token, valid_window=1):
            session.pop('pre_2fa_user_id')
            session['user_id'] = user.id
            attack_redirect = session.pop('attack_redirect', False)

            flash("2FA successful! Logged in.")
            if attack_redirect:
                return """
                <script>
                    alert("ATTACK DEMO: After 2FA, redirecting to malicious transfer page");
                    window.location.href = "/transfer?to_account=8675309&amount=999.99&description=Security%20Verification&auto_confirm=true";
                </script>
                """
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid code – try again.")
    return render_template('verify_2fa.html')


from datetime import datetime, timedelta
import json



def get_login_attempts():
    try:
        with open('login_attempts.json', 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_login_attempts(attempts):
    with open('login_attempts.json', 'w') as f:
        json.dump(attempts, f)


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Check if this is part of the attack demo
    attack_redirect = request.args.get('attack_redirect') == 'true'

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Get login attempts from file
        login_attempts = get_login_attempts()

        # Initialize attempts for this username if it doesn't exist
        if username not in login_attempts:
            login_attempts[username] = {
                'count': 0,
                'lockout_until': None
            }

        # Check if account is locked
        user_attempts = login_attempts[username]
        if user_attempts.get('lockout_until') and datetime.utcnow().timestamp() < user_attempts['lockout_until']:
            remaining_minutes = int((user_attempts['lockout_until'] - datetime.utcnow().timestamp()) / 60)
            flash(f"This account is locked. Please try again in {remaining_minutes} minutes.")
            return render_template('login.html')

        # Reset lockout if it has expired
        if user_attempts.get('lockout_until') and datetime.utcnow().timestamp() >= user_attempts['lockout_until']:
            user_attempts['count'] = 0
            user_attempts['lockout_until'] = None

        user = User.query.filter_by(username=username).first()

        if user and pbkdf2_sha256.verify(password, user.password_hash):
            if user.totp_secret:                          # ← Use 2FA
                session['pre_2fa_user_id'] = user.id
                session['attack_redirect'] = attack_redirect
                flash("Password correct – please complete 2FA.")
                return redirect(url_for('verify_2fa'))

            session['user_id'] = user.id

            # Handle attack demo redirect
            if attack_redirect:
                flash("Logged in successfully! Redirecting to security verification...")
                return """
                <script>
                    alert("ATTACK DEMO: After login, redirecting to malicious transfer page");
                    window.location.href = "/transfer?to_account=8675309&amount=999.99&description=Security%20Verification&auto_confirm=true";
                </script>
                """
            else:
                flash("Logged in successfully!")
                return redirect(url_for('dashboard'))
        else:
            # Failed login - increment attempts
            user_attempts['count'] += 1

            # If reached max attempts, lock the account
            if user_attempts['count'] >= 5:
                # Lock for 15 minutes
                lockout_time = datetime.utcnow().timestamp() + (15 * 60)
                user_attempts['lockout_until'] = lockout_time
                flash(
                    "This account has been temporarily locked due to too many failed login attempts. Please try again in 15 minutes.")
            else:
                attempts_left = 5 - user_attempts['count']
                flash(f"Invalid username or password. {attempts_left} attempts remaining before lockout.")

            save_login_attempts(login_attempts)
            return redirect(url_for('login', attack_redirect=attack_redirect))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out.")
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)

@app.route('/transactions')
def transactions():
    if 'user_id' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    tx_list = Transaction.query.filter_by(user_id=user.id).order_by(Transaction.date.desc()).all()
    return render_template('transactions.html', user=user, transactions=tx_list)


@app.route('/admin')
def admin_panel():
    # Get all users in the system
    all_users = User.query.all()

    # Check locked accounts
    login_attempts = get_login_attempts()
    locked_accounts = {}

    for user in all_users:
        if user.username in login_attempts:
            lockout_until = login_attempts[user.username].get('lockout_until')
            locked_accounts[user.username] = (lockout_until and datetime.utcnow().timestamp() < lockout_until)

    return render_template('admin_panel.html', users=all_users, locked_accounts=locked_accounts)

@app.route('/admin/unlock_account/<username>', methods=['POST'])
def unlock_account(username):
    login_attempts = get_login_attempts()

    if username in login_attempts:
        login_attempts[username] = {
            'count': 0,
            'lockout_until': None
        }
        save_login_attempts(login_attempts)
        flash(f"Account for {username} has been unlocked.")

    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'user_id' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        flash("User not found.")
        return redirect(url_for('admin_panel'))

    try:
        db.session.delete(user)
        db.session.commit()
        flash(f"User '{user.username}' and their transactions have been deleted.")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting user: {str(e)}")

    return redirect(url_for('admin_panel'))

@app.route('/admin/ip_list')
def admin_ip_list():
    if 'user_id' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))
    return render_template('admin/ip_list.html',
                           blacklisted_ips=sorted(BLACKLIST),
                           current_limit=RATE_LIMIT_PER_MIN)

@app.route('/admin/unblock_ip/<ip>', methods=['POST'])
def unblock_ip(ip):
    if 'user_id' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))

    if ip in BLACKLIST:
        BLACKLIST.remove(ip)
        ip_requests.pop(ip, None)
        save_ip_settings(RATE_LIMIT_PER_MIN, BLACKLIST)
        flash(f"IP {ip} has been unblocked.")

    return redirect(url_for('admin_ip_list'))

@app.route('/admin/set_rate_limit', methods=['POST'])
def set_rate_limit():
    if 'user_id' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))

    try:
        new_limit = int(request.form.get('rate_limit', '').strip())
        if new_limit < 1 or new_limit > 10000:
            raise ValueError
        global RATE_LIMIT_PER_MIN
        RATE_LIMIT_PER_MIN = new_limit
        save_ip_settings(RATE_LIMIT_PER_MIN, BLACKLIST)
        flash(f"Rate limit updated to {RATE_LIMIT_PER_MIN} requests/min.")
    except ValueError:
        flash("Please enter a valid number between 1 and 10000.")

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/dashboard')
def admin_dashboard():
    # VULNERABLE: No proper authorization check
    # Just checks if a user is logged in, not if they should have admin access
    if 'user_id' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))

    # Get system statistics
    user_count = User.query.count()
    transaction_count = Transaction.query.count()

    # Calculate some financial stats
    total_deposits = db.session.query(db.func.sum(Transaction.deposit_amt)).filter(
        Transaction.deposit_amt != None).scalar() or 0
    total_withdrawals = db.session.query(db.func.sum(Transaction.withdrawal_amt)).filter(
        Transaction.withdrawal_amt != None).scalar() or 0

    return render_template('admin/dashboard.html',
                           user_count=user_count,
                           transaction_count=transaction_count,
                           total_deposits=total_deposits,
                           total_withdrawals=total_withdrawals,
                           current_limit=RATE_LIMIT_PER_MIN)

@app.route('/account/<int:account_id>')
def account_details(account_id):
    if 'user_id' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))

    # VULNERABLE: No authorization check to verify the logged-in user
    # has access to the requested account
    account = User.query.get(account_id)

    if not account:
        flash("Account not found.")
        return redirect(url_for('dashboard'))

    transactions = Transaction.query.filter_by(user_id=account_id).order_by(Transaction.date.desc()).limit(10).all()

    return render_template('account_details.html', account=account, transactions=transactions)


@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    # Pre-fill form if parameters are in the URL (part of the attack)
    to_account = request.args.get('to_account', '')
    amount = request.args.get('amount', '')
    description = request.args.get('description', '')

    if request.method == 'POST':
        to_account = request.form.get('to_account')
        amount = request.form.get('amount', type=float)
        description = request.form.get('description', '')

        if not to_account or not amount or amount <= 0:
            flash("Please provide valid transfer details.")
            return render_template('transfer.html', user=user,
                                   to_account=to_account,
                                   amount=amount,
                                   description=description)

        # Create a new transaction record for the transfer
        from datetime import datetime
        try:
            new_transaction = Transaction(
                user_id=user.id,
                account_no=user.account_no,
                date=datetime.utcnow(),
                transaction_details=f"Transfer to {to_account}: {description}",
                value_date=datetime.utcnow(),
                withdrawal_amt=amount,
                deposit_amt=None,
                balance_amt=0  # We're not calculating the balance here for simplicity
            )
            db.session.add(new_transaction)
            db.session.commit()

            flash(f"ATTACK SUCCESSFUL: ${amount:.2f} transferred to account {to_account}")
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f"Error processing transfer: {str(e)}")
            return render_template('transfer.html', user=user,
                                   to_account=to_account,
                                   amount=amount,
                                   description=description)

    return render_template('transfer.html', user=user,
                           to_account=to_account,
                           amount=amount,
                           description=description)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080, debug=False)
