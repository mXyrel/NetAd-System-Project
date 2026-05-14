"""
Authentication Routes
=====================
Handles: login, logout.
All attempts (success AND failure) are permanently logged.
Brute-force detection fires an Alert when a single IP fails 5+ times in 10 minutes.
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_user, logout_user, login_required, current_user
from models.models import User, LoginLog, Alert
from extensions import db, limiter
from datetime import datetime, timedelta

auth_bp = Blueprint('auth', __name__)


def _get_client_ip() -> str:
    """Extracts real client IP, accounting for Railway / proxy headers."""
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'


def _check_and_flag_brute_force(ip: str):
    """If an IP has 5+ failed logins in the last 10 minutes, raise a critical alert."""
    cutoff = datetime.utcnow() - timedelta(minutes=10)
    recent_fails = LoginLog.query.filter(
        LoginLog.ip_address == ip,
        LoginLog.success == False,
        LoginLog.timestamp >= cutoff
    ).count()

    if recent_fails >= 5:
        # Only create one unresolved brute-force alert per IP
        existing = Alert.query.filter_by(
            alert_type='brute_force',
            ip_address=ip,
            resolved=False
        ).first()
        if not existing:
            alert = Alert(
                alert_type='brute_force',
                message=f'Brute-force detected: {recent_fails} failed login attempts from {ip} in the last 10 minutes.',
                ip_address=ip,
                severity='critical'
            )
            db.session.add(alert)


# ── Login ────────────────────────────────────────────────────────────────────
@auth_bp.route('/', methods=['GET', 'POST'])
@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("20 per minute")   # Rate limit the login endpoint
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    error = None

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        ip       = _get_client_ip()
        ua       = (request.user_agent.string or '')[:512]

        user = User.query.filter_by(username=username).first()
        login_ok = bool(user and user.is_active and user.check_password(password))

        # ── Always log the attempt ────────────────────────────────────────
        log = LoginLog(
            user_id=user.id if (user and login_ok) else None,
            username_attempted=username,
            ip_address=ip,
            user_agent=ua,
            success=login_ok,
            action='login'
        )
        db.session.add(log)

        if login_ok:
            user.last_login = datetime.utcnow()
            db.session.commit()

            login_user(user, remember=False)

            # Redirect to the originally requested page, or dashboard
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):   # prevent open-redirect
                return redirect(next_page)
            return redirect(url_for('dashboard.index'))
        else:
            _check_and_flag_brute_force(ip)
            db.session.commit()
            error = 'Invalid username or password.'

    return render_template('login.html', error=error)


# ── Logout ───────────────────────────────────────────────────────────────────
@auth_bp.route('/logout')
@login_required
def logout():
    ip = _get_client_ip()
    log = LoginLog(
        user_id=current_user.id,
        username_attempted=current_user.username,
        ip_address=ip,
        user_agent=(request.user_agent.string or '')[:512],
        success=True,
        action='logout'
    )
    db.session.add(log)
    db.session.commit()

    logout_user()
    flash('You have been securely logged out.', 'info')
    return redirect(url_for('auth.login'))
