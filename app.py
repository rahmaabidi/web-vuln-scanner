from flask import Flask, request, render_template, redirect, url_for, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from scanner.headers import analyze_headers
from scanner.cookies import analyze_cookies
from scanner.xss import test_xss
from scanner.sql import test_sql_injection
from scanner.ssl_check import check_ssl_cert
from forms import LoginForm, RegisterForm
from models import db, User, Scan
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from scanner.crawler import crawl_site
import json
from pdf_utils import html_to_pdf

app = Flask(__name__)
app.config['SECRET_KEY'] = 'yoursecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scanner.db'

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
def home():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid email or password')
    return render_template('login.html', form=form)

@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    results = None
    url = None
    scan_id = None
    profile = None

    if request.method == 'POST':
        url = request.form.get('url')
        profile = request.form.get('profile', 'quick')

        if url:
            if profile == "quick":
                hostname = urlparse(url).hostname or url
                results = {
                    'headers': analyze_headers(url),
                    'ssl': check_ssl_cert(hostname),
                }
            else:
                crawled_urls = crawl_site(url, limit=5)
                aggregate_results = {}

                for target_url in crawled_urls:
                    hostname = urlparse(target_url).hostname or target_url
                    with ThreadPoolExecutor() as executor:
                        futures = {
                            'headers': executor.submit(analyze_headers, target_url),
                            'cookies': executor.submit(analyze_cookies, target_url),
                            'xss': executor.submit(test_xss, target_url),
                            'sqli': executor.submit(test_sql_injection, target_url),
                            'ssl': executor.submit(check_ssl_cert, hostname),
                        }
                        scan_results = {key: task.result() for key, task in futures.items()}
                    aggregate_results[target_url] = scan_results

                results = aggregate_results

            scan = Scan(user_id=current_user.id, url=url, results=json.dumps(results))
            db.session.add(scan)
            db.session.commit()
            scan_id = scan.id

    return render_template("index.html", results=results, url=url, scan_id=scan_id, profile=profile)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email already registered')
        else:
            new_user = User(email=form.email.data)
            new_user.set_password(form.password.data)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful. Please log in.')
            return redirect(url_for('home'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    scans = Scan.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', scans=scans)

@app.route('/download_report/<int:scan_id>')
@login_required
def download_report(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        return "Unauthorized", 403

    try:
        # Ensure deserialization happens here
        raw_results = json.loads(scan.results)
    except (json.JSONDecodeError, TypeError):
        raw_results = {}

    html = render_template('report_template.html', scan=scan, results=raw_results)
    pdf = html_to_pdf(html)

    if not pdf:
        return "Failed to generate PDF", 500

    response = make_response(pdf.read())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=scan_report_{scan_id}.pdf'
    return response


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
