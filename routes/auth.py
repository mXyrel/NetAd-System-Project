"""
Authentication Routes — Security Hardened
==========================================
Security layers added:
  1. IP Block check    — blocked IPs are rejected before any DB query
  2. Account lockout   — 5 fails = 15 min lock, logged with reason
  3. Login delay       — 0.5s artificial delay on every failed attempt
  4. Brute force alert — critical alert at 5 fails/10min from same IP
  5. Auto IP block     — 15+ fails in 1 hour triggers automatic IP block
  6. New IP alert      — alert when admin logs in from new IP
  7. Constant-time     — timing attack prevention via hmac.compare_digest
  8. CSRF token check  — validates hidden token on every POST
"""

import time
import hmac
import hashlib
import secrets
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash
from models.models import User, LoginLog, Alert, BlockedIP
from extensions import db, limiter
from datetime import datetime, timedelta

auth_bp = Blueprint('auth', __name__)

# ── CSRF token helpers ────────────────────────────────────────────────────────
def _generate_csrf_token() -> str:
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def _validate_csrf_token() -> bool:
    token_in_form    = request.form.get('csrf_token', '')
    token_in_session = session.get('csrf_token', '')
    if not token_in_form or not token_in_session:
        return False
    # Use hmac to prevent timing attacks on the comparison
    return hmac.compare_digest(token_in_form, token_in_session)

# ── Client IP extraction ──────────────────────────────────────────────────────
def _get_client_ip() -> str:
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'

# ── Check if IP is blocked ────────────────────────────────────────────────────
def _is_ip_blocked(ip: str) -> bool:
    block = BlockedIP.query.filter_by(ip_address=ip).first()
    if block and block.is_active():
        return True
    return False

# ── Auto-block IP after excessive failures ────────────────────────────────────
def _maybe_auto_block_ip(ip: str):
    cutoff = datetime.utcnow() - timedelta(hours=1)
    fails_last_hour = LoginLog.query.filter(
        LoginLog.ip_address == ip,
        LoginLog.success    == False,
        LoginLog.timestamp  >= cutoff
    ).count()

    if fails_last_hour >= 15:
        existing = BlockedIP.query.filter_by(ip_address=ip).first()
        if not existing:
            block = BlockedIP(
                ip_address=ip,
                reason=f'Auto-blocked: {fails_last_hour} failed attempts in 1 hour',
                blocked_by='system',
                expires_at=datetime.utcnow() + timedelta(hours=24)
            )
            db.session.add(block)
            alert = Alert(
                alert_type='ip_auto_blocked',
                message=f'IP {ip} automatically blocked after {fails_last_hour} failed login attempts.',
                ip_address=ip,
                severity='critical'
            )
            db.session.add(alert)

# ── Brute force alert ─────────────────────────────────────────────────────────
def _check_and_flag_brute_force(ip: str):
    cutoff = datetime.utcnow() - timedelta(minutes=10)
    recent_fails = LoginLog.query.filter(
        LoginLog.ip_address == ip,
        LoginLog.success    == False,
        LoginLog.timestamp  >= cutoff
    ).count()

    if recent_fails >= 5:
        existing = Alert.query.filter_by(
            alert_type='brute_force',
            ip_address=ip,
            resolved=False
        ).first()
        if not existing:
            db.session.add(Alert(
                alert_type='brute_force',
                message=f'Brute-force detected: {recent_fails} failed attempts from {ip} in 10 min.',
                ip_address=ip,
                severity='critical'
            ))

# ── Alert if admin logs in from a new IP ─────────────────────────────────────
def _check_new_ip_login(user: User, ip: str):
    if user.is_admin() and user.last_ip and user.last_ip != ip:
        db.session.add(Alert(
            alert_type='new_ip_login',
            message=f'Admin "{user.username}" logged in from new IP {ip} (previous: {user.last_ip})',
            ip_address=ip,
            severity='high'
        ))

# ═════════════════════════════════════════════════════════════════════════════
# LOGIN
# ═════════════════════════════════════════════════════════════════════════════
@auth_bp.route('/', methods=['GET', 'POST'])
@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))

    csrf_token = _generate_csrf_token()
    error = None

    if request.method == 'POST':

        # ── 1. CSRF validation ─────────────────────────────────────────────
        if not _validate_csrf_token():
            db.session.add(Alert(
                alert_type='csrf_violation',
                message=f'CSRF token mismatch from {_get_client_ip()}',
                ip_address=_get_client_ip(),
                severity='high'
            ))
            db.session.commit()
            error = 'Invalid request. Please try again.'
            return render_template('login.html', error=error, csrf_token=_generate_csrf_token())

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        ip       = _get_client_ip()
        ua       = (request.user_agent.string or '')[:512]

        # ── 2. IP block check ──────────────────────────────────────────────
        if _is_ip_blocked(ip):
            db.session.add(LoginLog(
                username_attempted=username,
                ip_address=ip,
                user_agent=ua,
                success=False,
                action='login',
                failure_reason='ip_blocked'
            ))
            db.session.commit()
            error = 'Access denied.'
            time.sleep(0.5)
            return render_template('login.html', error=error, csrf_token=_generate_csrf_token())

        # ── 3. Look up user (always do full lookup to prevent user enumeration) ──
        user     = User.query.filter_by(username=username).first()

        # ── 4. Account lockout check ───────────────────────────────────────
        if user and user.is_locked():
            mins = user.lock_minutes_remaining()
            db.session.add(LoginLog(
                user_id=user.id,
                username_attempted=username,
                ip_address=ip,
                user_agent=ua,
                success=False,
                action='login',
                failure_reason='account_locked'
            ))
            db.session.commit()
            time.sleep(0.5)
            error = f'Account locked due to too many failed attempts. Try again in {mins} minute(s).'
            return render_template('login.html', error=error, csrf_token=_generate_csrf_token())

        # ── 5. Constant-time password check ───────────────────────────────
        # Always run check_password even if user is None (prevents timing attacks)
        if user and user.is_active:
            login_ok = user.check_password(password)
        else:
            # Run a dummy hash check so response time is the same whether user exists or not
            generate_password_hash('dummy_timing_protection')
            login_ok = False

        # ── 6. Log the attempt ─────────────────────────────────────────────
        failure_reason = None
        if not login_ok:
            if not user:
                failure_reason = 'user_not_found'
            elif not user.is_active:
                failure_reason = 'inactive_account'
            else:
                failure_reason = 'bad_password'

        log = LoginLog(
            user_id=user.id if (user and login_ok) else None,
            username_attempted=username,
            ip_address=ip,
            user_agent=ua,
            success=login_ok,
            action='login',
            failure_reason=failure_reason
        )
        db.session.add(log)

        # ── 7. Handle success ──────────────────────────────────────────────
        if login_ok:
            _check_new_ip_login(user, ip)
            user.record_successful_login()
            user.last_login = datetime.utcnow()
            user.last_ip    = ip
            db.session.commit()
            login_user(user, remember=False)

            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('dashboard.index'))

        # ── 8. Handle failure ──────────────────────────────────────────────
        else:
            if user:
                user.record_failed_login()
            _check_and_flag_brute_force(ip)
            _maybe_auto_block_ip(ip)
            db.session.commit()

            # Artificial delay — slows brute force, attacker can't loop fast
            time.sleep(0.5)
            error = 'Invalid username or password.'

    return render_template('login.html', error=error, csrf_token=csrf_token)


# ═════════════════════════════════════════════════════════════════════════════
# LOGOUT
# ═════════════════════════════════════════════════════════════════════════════
@auth_bp.route('/logout')
@login_required
def logout():
    ip = _get_client_ip()
    db.session.add(LoginLog(
        user_id=current_user.id,
        username_attempted=current_user.username,
        ip_address=ip,
        user_agent=(request.user_agent.string or '')[:512],
        success=True,
        action='logout'
    ))
    db.session.commit()
    logout_user()
    session.clear()
    flash('You have been securely logged out.', 'info')
    return redirect(url_for('auth.login'))
