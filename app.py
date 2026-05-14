"""
Network Hardware Monitoring & Protection System
================================================
Main application entry point.
Uses the Application Factory pattern so the app can be tested and configured easily.
"""

import os
from flask import Flask, request, g
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

# ── Import extensions from their dedicated module ──────────────────────────
# They live in extensions.py — NOT here — to avoid circular imports.
from extensions import db, login_manager, limiter


def create_app():
    app = Flask(__name__)

    # ── Configuration ───────────────────────────────────────────────────────
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'CHANGE-THIS-IN-PRODUCTION')

    # Railway gives DATABASE_URL starting with postgres:// — SQLAlchemy needs postgresql://
    db_url = os.environ.get('DATABASE_URL', 'sqlite:///monitor.db')
    if db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # ── Session / cookie hardening ──────────────────────────────────────────
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    # Set SECURE only in production (HTTPS)
    app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'
    app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 min session timeout

    # ── Initialize extensions ───────────────────────────────────────────────
    db.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)

    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access the monitoring dashboard.'
    login_manager.login_message_category = 'warning'

    # ── Register blueprints ─────────────────────────────────────────────────
    from routes.auth import auth_bp
    from routes.dashboard import dashboard_bp
    from routes.api import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(api_bp, url_prefix='/api')

    # ── Create tables + seed admin on first run ─────────────────────────────
    with app.app_context():
        db.create_all()
        _seed_initial_data()

    # ── Request timing (useful for performance logs) ─────────────────────────
    @app.before_request
    def before_request():
        g.start_time = datetime.utcnow()

    # ── Security headers on every response ──────────────────────────────────
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response

    return app


def _seed_initial_data():
    """Create the default admin account and sample devices on first boot."""
    from models.models import User, Device

    # ── Admin user ───────────────────────────────────────────────────────────
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', role='admin')
        admin.set_password(os.environ.get('ADMIN_PASSWORD', 'Admin@1234!'))
        db.session.add(admin)
        print('[SETUP] Admin user created. Change the default password immediately!')

    # ── Default devices ──────────────────────────────────────────────────────
    default_devices = [
        {'name': 'IP Camera 01',  'device_type': 'camera', 'ip_address': '192.168.1.100', 'stream_url': ''},
        {'name': 'Main Router',   'device_type': 'router', 'ip_address': '192.168.1.1',   'stream_url': ''},
        {'name': 'Network Switch','device_type': 'switch', 'ip_address': '192.168.1.2',   'stream_url': ''},
    ]
    for d in default_devices:
        if not Device.query.filter_by(name=d['name']).first():
            db.session.add(Device(**d))

    db.session.commit()


# ── Run directly (development only) ─────────────────────────────────────────
app = create_app()

if __name__ == '__main__':
    app.run(
        debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true',
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000))
    )
