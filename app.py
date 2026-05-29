"""
Network Hardware Monitoring & Protection System
================================================
Security hardened app.py:
  - SECRET_KEY validation — refuses to start in production without it
  - HTTPS redirect in production
  - Full Content Security Policy header
  - Session fingerprinting — detects stolen session cookies
  - Talisman-style security headers
"""

import os
import hashlib
from flask import Flask, request, g, redirect, session
from flask_login import current_user, logout_user
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

from extensions import db, login_manager, limiter


def create_app():
    app = Flask(__name__)

    # ── SECRET_KEY — hard fail if not set in production ──────────────────────
    secret_key = os.environ.get('SECRET_KEY')
    if not secret_key or secret_key == 'CHANGE-THIS-IN-PRODUCTION':
        if os.environ.get('FLASK_ENV') == 'production':
            raise RuntimeError(
                '[FATAL] SECRET_KEY is not set or is using the default value. '
                'Set a strong SECRET_KEY in Railway environment variables before deploying.'
            )
        secret_key = 'dev-only-insecure-key-do-not-use-in-production'
    app.config['SECRET_KEY'] = secret_key

    # ── Database ──────────────────────────────────────────────────────────────
    db_url = os.environ.get('DATABASE_URL', 'sqlite:///monitor.db')
    if db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # ── Session / cookie hardening ────────────────────────────────────────────
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE']   = os.environ.get('FLASK_ENV') == 'production'
    app.config['SESSION_COOKIE_NAME']     = '__Host_session' if os.environ.get('FLASK_ENV') == 'production' else 'session'
    app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes

    # ── Initialize extensions ──────────────────────────────────────────────
    db.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)

    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access the monitoring dashboard.'
    login_manager.login_message_category = 'warning'

    # ── Register blueprints ────────────────────────────────────────────────
    from routes.auth import auth_bp
    from routes.dashboard import dashboard_bp
    from routes.api import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(api_bp, url_prefix='/api')

    # ── Create tables + seed data ─────────────────────────────────────────
    with app.app_context():
        db.create_all()
        _run_migrations()
        _seed_initial_data()

    # ── HTTPS redirect in production ──────────────────────────────────────
    @app.before_request
    def force_https():
        if os.environ.get('FLASK_ENV') == 'production':
            forwarded_proto = request.headers.get('X-Forwarded-Proto', '')
            if forwarded_proto == 'http':
                url = request.url.replace('http://', 'https://', 1)
                return redirect(url, code=301)

    # ── Session fingerprinting — detects stolen session cookies ──────────
    @app.before_request
    def check_session_fingerprint():
        if current_user.is_authenticated:
            fingerprint = hashlib.sha256(
                (
                    request.user_agent.string +
                    request.headers.get('Accept-Language', '') +
                    request.headers.get('Accept-Encoding', '')
                ).encode()
            ).hexdigest()[:24]

            stored = session.get('fp')
            if stored is None:
                session['fp'] = fingerprint
            elif not (len(stored) == len(fingerprint) and
                      all(a == b for a, b in zip(stored, fingerprint))):
                logout_user()
                session.clear()
                from flask import flash
                flash('Session expired for security reasons. Please log in again.', 'warning')
                from flask import url_for
                return redirect(url_for('auth.login'))

    # ── Request timestamp ──────────────────────────────────────────────────
    @app.before_request
    def before_request():
        g.start_time = datetime.utcnow()

    # ── Security headers on every single response ─────────────────────────
    @app.after_request
    def set_security_headers(response):
        # Prevent MIME sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        # Block iframe embedding (clickjacking)
        response.headers['X-Frame-Options'] = 'DENY'
        # XSS protection for older browsers
        response.headers['X-XSS-Protection'] = '1; mode=block'
        # Referrer control
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        # Permissions policy
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), payment=()'
        # Content Security Policy — restricts what can load on the page
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' data: blob: *; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        # HSTS — only in production
        if os.environ.get('FLASK_ENV') == 'production':
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        # Remove server version header
        response.headers.pop('Server', None)
        response.headers.pop('X-Powered-By', None)
        return response

    return app


def _run_migrations():
    """
    Safe column migrations for both SQLite (local) and PostgreSQL (Railway).
    Each column gets its own transaction so one failure never blocks the others.
    Uses TIMESTAMP for PostgreSQL, DATETIME for SQLite.
    """
    from sqlalchemy import text, inspect
    engine = db.engine

    # Detect database type
    is_postgres = 'postgresql' in str(engine.url) or 'postgres' in str(engine.url)
    timestamp_type = 'TIMESTAMP' if is_postgres else 'DATETIME'
    bool_default   = 'FALSE'     if is_postgres else '0'

    inspector = inspect(engine)

    # ── users table ──────────────────────────────────────────────────────────
    existing_cols = [c['name'] for c in inspector.get_columns('users')]
    new_cols = {
        'failed_login_count':   f'INTEGER DEFAULT 0',
        'locked_until':         f'{timestamp_type}',
        'last_ip':              f'VARCHAR(45)',
        'must_change_password': f'BOOLEAN DEFAULT {bool_default}',
    }

    for col, col_type in new_cols.items():
        if col not in existing_cols:
            # Each column gets its own connection + transaction
            with engine.connect() as conn:
                try:
                    conn.execute(text(f'ALTER TABLE users ADD COLUMN {col} {col_type}'))
                    conn.commit()
                    print(f'[MIGRATION] Added column users.{col}')
                except Exception as e:
                    conn.rollback()
                    print(f'[MIGRATION] Skipping users.{col}: {e}')

    # ── login_logs table ──────────────────────────────────────────────────────
    if 'login_logs' in inspector.get_table_names():
        log_cols = [c['name'] for c in inspector.get_columns('login_logs')]
        if 'failure_reason' not in log_cols:
            with engine.connect() as conn:
                try:
                    conn.execute(text('ALTER TABLE login_logs ADD COLUMN failure_reason VARCHAR(50)'))
                    conn.commit()
                    print('[MIGRATION] Added column login_logs.failure_reason')
                except Exception as e:
                    conn.rollback()
                    print(f'[MIGRATION] Skipping login_logs.failure_reason: {e}')

    # ── blocked_ips table (new table — create_all handles it, but verify) ────
    if 'blocked_ips' not in inspector.get_table_names():
        print('[MIGRATION] blocked_ips table will be created by db.create_all()')



def _seed_initial_data():
    from models.models import User, Device

    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', role='admin')
        admin.set_password(os.environ.get('ADMIN_PASSWORD', 'Admin@1234!'))
        db.session.add(admin)
        print('[SETUP] Admin user created. Change the default password immediately!')

    default_devices = [
        {'name': 'IP Camera 01',   'device_type': 'camera', 'ip_address': '192.168.1.100', 'stream_url': ''},
        {'name': 'Main Router',    'device_type': 'router', 'ip_address': '192.168.1.1',   'stream_url': ''},
        {'name': 'Network Switch', 'device_type': 'switch', 'ip_address': '192.168.1.2',   'stream_url': ''},
    ]
    for d in default_devices:
        if not Device.query.filter_by(name=d['name']).first():
            db.session.add(Device(**d))

    db.session.commit()


app = create_app()

if __name__ == '__main__':
    app.run(
        debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true',
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000))
    )
