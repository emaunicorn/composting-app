# ======= IMPORTS ========
# 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
from flask import Flask, render_template, request, redirect, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from dotenv import load_dotenv
from sqlalchemy import func, and_
import os

# ======= APP SETUP ========
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///compost.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
load_dotenv()  # Load environment variables from .env
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# ======= EMAIL SETUP =======
# Mail config (use your own email if not Gmail)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASS')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('EMAIL_USER')

mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])  # for secure tokens


# ======= DATABASE SETUP ========
db = SQLAlchemy(app)

# ======= LOGIN MANAGER SETUP ========
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to login if @login_required fails

# ======= USER LOADER FOR FLASK-LOGIN ========
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ======= MODELS ========

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    compost_logs = db.relationship('CompostDropoff', backref='user', lazy=True)
    is_admin = db.Column(db.Boolean, default=False)
    confirmed = db.Column(db.Boolean, default=False)

class CompostDropoff(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    weight = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # Link to User table

# ======= ROUTES ========

# Signup route
@app.route("/signup", methods=["GET", "POST"])
def signup():
    error = None

    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        if not name or not email or not password:
            error = "Please fill out all fields."
        elif User.query.filter_by(email=email).first():
            error = "An account with that email already exists."
        else:
            hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
            # ✅ Create user first, with confirmed=False
            new_user = User(name=name, email=email, password=hashed_pw, confirmed=False)
            db.session.add(new_user)
            db.session.commit()

            # ✅ Then send confirmation email
            token = s.dumps(email, salt='email-confirm')
            confirm_url = f"http://127.0.0.1:5000/confirm/{token}"
            msg = Message("Confirm Your Composting Account", recipients=[email])
            msg.body = f"Hi {name}, please confirm your account by clicking this link: {confirm_url}"
            mail.send(msg)

            return "A confirmation email has been sent. Please check your inbox."

    return render_template("signup.html", error=error)


# Comfirm token route
@app.route("/confirm/<token>")
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)  # 1 hour
    except SignatureExpired:
        return "This confirmation link has expired."
    except BadSignature:
        return "Invalid confirmation link."

    user = User.query.filter_by(email=email).first()
    if user:
        user.confirmed = True
        db.session.commit()
        return '''
            <h3>Your account has been confirmed ✅</h3>
            <p><a href="/dashboard">Click here to return to the homepage</a></p>
        '''    
    return "Account not found."


# Login route
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()

        if not user:
            error = "No account found with that email."
        elif not check_password_hash(user.password, password):
            error = "Incorrect password. Please try again."
        elif not user.confirmed:
            error = "Please confirm your account before logging in. Check your email."
        else:
            login_user(user)
            return redirect("/dashboard")

    return render_template("login.html", error=error)


# Send reset password link route
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    message = None
    if request.method == "POST":
        email = request.form["email"]
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(email, salt='password-reset')
            reset_url = f"http://127.0.0.1:5000/reset-password/{token}"
            msg = Message("Reset Your Composting Account Password", recipients=[email])
            msg.body = f"Click the link to reset your password: {reset_url}"
            mail.send(msg)
            message = "A password reset link has been sent to your email."
        else:
            message = "No account with that email."
    return render_template("forgot_password.html", message=message)


# Reset password route
@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)
    except SignatureExpired:
        return "Reset link has expired."
    except BadSignature:
        return "Invalid reset link."

    if request.method == "POST":
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()
        user.password = generate_password_hash(password, method='pbkdf2:sha256')
        db.session.commit()
        return redirect("/login")

    return '''
        <form method="POST">
            <input type="password" name="password" placeholder="New password" required>
            <button type="submit">Reset Password</button>
        </form>
    '''

# Logout route
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/dashboard")


# Dashboard route
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

# Admid dashboard route
from flask import request, render_template
from sqlalchemy import func, and_

@app.route("/admin-dashboard")
@login_required
def admin_dashboard():
    # Ensure only admin users can access this page
    if not current_user.is_authenticated or not current_user.is_admin:
        return "Unauthorized", 403

    # --- Get filter parameters from query string ---
    start_date = request.args.get("start_date", "")
    end_date = request.args.get("end_date", "")
    user_email = request.args.get("user_email", "")
    min_weight = request.args.get("min_weight", "")
    max_weight = request.args.get("max_weight", "")

    filters = []

    # Filter by date range
    if start_date:
        filters.append(CompostDropoff.timestamp >= datetime.strptime(start_date, "%Y-%m-%d"))
    if end_date:
        filters.append(CompostDropoff.timestamp <= datetime.strptime(end_date, "%Y-%m-%d"))

    # Filter by user email
    if user_email:
        user = User.query.filter_by(email=user_email).first()
        if user:
            filters.append(CompostDropoff.user_id == user.id)

    # Filter by weight range
    if min_weight:
        filters.append(CompostDropoff.weight >= float(min_weight))
    if max_weight:
        filters.append(CompostDropoff.weight <= float(max_weight))

    # Query filtered logs
    logs = CompostDropoff.query.filter(and_(*filters)).order_by(CompostDropoff.timestamp.desc()).all()

    # Summary stats
    total_weight = round(sum(log.weight for log in logs), 2)
    user_ids = set(log.user_id for log in logs)
    user_count = len(user_ids)
    average_per_user = round(total_weight / user_count, 2) if user_count > 0 else 0

    users = User.query.all()

    return render_template(
        "admin_dashboard.html",
        logs=logs,
        users=users,
        start_date=start_date,
        end_date=end_date,
        selected_user_email=user_email,
        min_weight=min_weight,
        max_weight=max_weight,
        total_weight=total_weight,
        user_count=user_count,
        average_per_user=average_per_user
    )


# Log compost route
@app.route("/log", methods=["GET", "POST"])
@login_required
def log():
    if request.method == "POST":
        try:
            weight = float(request.form["weight"])
            if weight <= 0:
                raise ValueError("Weight must be a positive number.")
            new_log = CompostLog(user_id=current_user.id, weight=weight)
            db.session.add(new_log)
            db.session.commit()
            return render_template("log.html", success="Compost logged successfully!")
        except ValueError as e:
            return render_template("log.html", error=str(e))
    return render_template("log.html")



# Composting history route
@app.route("/history")
@login_required
def history():
    logs = CompostDropoff.query.filter_by(user_id=current_user.id).order_by(CompostDropoff.timestamp.desc()).all()
    return render_template("history.html", logs=logs)

# User stats route
@app.route("/stats")
@login_required
def stats():
    # --- USER STATS ---
    user_id = current_user.id

    # Total composted by user
    user_total = db.session.query(func.sum(CompostDropoff.weight))\
        .filter_by(user_id=user_id).scalar() or 0

    # Weekly and monthly windows
    now = datetime.utcnow()
    week_ago = now - timedelta(days=7)
    month_ago = now - timedelta(days=30)

    # This week
    user_week = db.session.query(func.sum(CompostDropoff.weight))\
        .filter(CompostDropoff.user_id == user_id)\
        .filter(CompostDropoff.timestamp >= week_ago).scalar() or 0

    # This month
    user_month = db.session.query(func.sum(CompostDropoff.weight))\
        .filter(CompostDropoff.user_id == user_id)\
        .filter(CompostDropoff.timestamp >= month_ago).scalar() or 0

    # --- COMMUNITY STATS ---

    # Total composted by all users
    community_total = db.session.query(func.sum(CompostDropoff.weight)).scalar() or 0

    return render_template(
        "stats.html",
        user_total=round(user_total, 2),
        user_week=round(user_week, 2),
        user_month=round(user_month, 2),
        community_total=round(community_total, 2)
    )


# ======= RUN APP ========
if __name__ == "__main__":
    app.run(debug=True)
