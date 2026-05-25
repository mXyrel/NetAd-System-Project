"""
Dashboard Routes — Security Hardened
======================================
Added:
  - IP blocking management (admin can block/unblock IPs manually)
  - Password strength enforcement on user creation and change
  - Input sanitization on all form fields
  - Access attempt logging for sensitive admin actions
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from models.models import User, LoginLog, Device, AccessLog, Alert, BlockedIP
from extensions import db
from security.helpers import is_strong_password, sanitize_input
from datetime import datetime, timedelta
from functools import wraps

dashboard_bp = Blueprint('dashboard', __name__)


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin():
            db.session.add(Alert(
                alert_type='unauthorized_access',
                message=f'User "{current_user.username}" attempted to access admin page: {request.path}',
                ip_address=request.remote_addr,
                severity='medium'
            ))
            db.session.commit()
            flash('Administrator access required.', 'danger')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    return decorated


# ── Dashboard ─────────────────────────────────────────────────────────────────
@dashboard_bp.route('/dashboard')
@login_required
def index():
    devices       = Device.query.all()
    online_count  = sum(1 for d in devices if d.status == 'online')
    offline_count = sum(1 for d in devices if d.status == 'offline')

    today_start  = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    failed_today = LoginLog.query.filter(
        LoginLog.success == False,
        LoginLog.timestamp >= today_start
    ).count()

    total_logs        = LoginLog.query.count()
    unresolved_alerts = Alert.query.filter_by(resolved=False).order_by(Alert.timestamp.desc()).all()
    recent_logs       = LoginLog.query.order_by(LoginLog.timestamp.desc()).limit(20).all()
    camera            = Device.query.filter_by(device_type='camera').first()
    blocked_ips_count = BlockedIP.query.count()

    return render_template(
        'dashboard.html',
        devices=devices,
        online_count=online_count,
        offline_count=offline_count,
        failed_today=failed_today,
        total_logs=total_logs,
        unresolved_alerts=unresolved_alerts,
        recent_logs=recent_logs,
        camera=camera,
        blocked_ips_count=blocked_ips_count,
        now=datetime.utcnow()
    )


# ── Users ──────────────────────────────────────────────────────────────────────
@dashboard_bp.route('/users')
@admin_required
def users():
    all_users   = User.query.order_by(User.created_at.desc()).all()
    blocked_ips = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()
    return render_template('users.html', users=all_users, blocked_ips=blocked_ips)


@dashboard_bp.route('/users/add', methods=['POST'])
@admin_required
def add_user():
    username = sanitize_input(request.form.get('username', ''))
    password = request.form.get('password', '')
    role     = request.form.get('role', 'viewer')

    if role not in ('admin', 'viewer'):
        flash('Invalid role.', 'danger')
        return redirect(url_for('dashboard.users'))

    if not username or not password:
        flash('Username and password are required.', 'danger')
        return redirect(url_for('dashboard.users'))

    if User.query.filter_by(username=username).first():
        flash(f'Username "{username}" is already taken.', 'danger')
        return redirect(url_for('dashboard.users'))

    strong, reason = is_strong_password(password)
    if not strong:
        flash(reason, 'danger')
        return redirect(url_for('dashboard.users'))

    new_user = User(username=username, role=role)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    flash(f'User "{username}" created successfully.', 'success')
    return redirect(url_for('dashboard.users'))


@dashboard_bp.route('/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('dashboard.users'))
    db.session.delete(user)
    db.session.commit()
    flash(f'User "{user.username}" deleted.', 'success')
    return redirect(url_for('dashboard.users'))


@dashboard_bp.route('/users/change-password/<int:user_id>', methods=['POST'])
@admin_required
def change_password(user_id):
    user     = User.query.get_or_404(user_id)
    password = request.form.get('new_password', '')

    strong, reason = is_strong_password(password)
    if not strong:
        flash(reason, 'danger')
        return redirect(url_for('dashboard.users'))

    user.set_password(password)
    db.session.commit()
    flash(f'Password for "{user.username}" updated.', 'success')
    return redirect(url_for('dashboard.users'))


@dashboard_bp.route('/users/unlock/<int:user_id>', methods=['POST'])
@admin_required
def unlock_user(user_id):
    user = User.query.get_or_404(user_id)
    user.locked_until = None
    user.failed_login_count = 0
    db.session.commit()
    flash(f'Account "{user.username}" unlocked.', 'success')
    return redirect(url_for('dashboard.users'))


# ── IP Blocking ────────────────────────────────────────────────────────────────
@dashboard_bp.route('/ips/block', methods=['POST'])
@admin_required
def block_ip():
    ip     = sanitize_input(request.form.get('ip_address', ''))
    reason = sanitize_input(request.form.get('reason', 'Manually blocked by admin'))

    if not ip:
        flash('IP address is required.', 'danger')
        return redirect(url_for('dashboard.users'))

    existing = BlockedIP.query.filter_by(ip_address=ip).first()
    if existing:
        flash(f'{ip} is already blocked.', 'warning')
        return redirect(url_for('dashboard.users'))

    db.session.add(BlockedIP(
        ip_address=ip,
        reason=reason,
        blocked_by=current_user.username,
        expires_at=None  # permanent
    ))
    db.session.add(Alert(
        alert_type='ip_blocked',
        message=f'IP {ip} manually blocked by {current_user.username}. Reason: {reason}',
        ip_address=ip,
        severity='medium'
    ))
    db.session.commit()
    flash(f'IP {ip} has been blocked.', 'success')
    return redirect(url_for('dashboard.users'))


@dashboard_bp.route('/ips/unblock/<int:block_id>', methods=['POST'])
@admin_required
def unblock_ip(block_id):
    block = BlockedIP.query.get_or_404(block_id)
    ip    = block.ip_address
    db.session.delete(block)
    db.session.commit()
    flash(f'IP {ip} has been unblocked.', 'success')
    return redirect(url_for('dashboard.users'))


# ── Logs ──────────────────────────────────────────────────────────────────────
@dashboard_bp.route('/logs')
@login_required
def logs():
    page     = request.args.get('page', 1, type=int)
    log_type = request.args.get('type', 'all')

    query = LoginLog.query.order_by(LoginLog.timestamp.desc())
    if log_type == 'failed':
        query = query.filter_by(success=False)
    elif log_type == 'success':
        query = query.filter_by(success=True)

    pagination = query.paginate(page=page, per_page=50, error_out=False)
    return render_template('logs.html', pagination=pagination, log_type=log_type)


# ── Devices ───────────────────────────────────────────────────────────────────
@dashboard_bp.route('/devices/update/<int:device_id>', methods=['POST'])
@admin_required
def update_device(device_id):
    device            = Device.query.get_or_404(device_id)
    device.name       = sanitize_input(request.form.get('name', device.name))
    device.ip_address = sanitize_input(request.form.get('ip_address', device.ip_address))
    device.stream_url = request.form.get('stream_url', device.stream_url or '').strip()
    db.session.commit()
    flash(f'Device "{device.name}" updated.', 'success')
    return redirect(url_for('dashboard.index'))


# ── Alerts ────────────────────────────────────────────────────────────────────
@dashboard_bp.route('/alerts/resolve/<int:alert_id>', methods=['POST'])
@admin_required
def resolve_alert(alert_id):
    alert          = Alert.query.get_or_404(alert_id)
    alert.resolved = True
    db.session.commit()
    flash('Alert marked as resolved.', 'success')
    return redirect(url_for('dashboard.index'))
