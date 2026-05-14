"""
Dashboard Routes
================
The main authenticated section of the application.
All routes require login. Admin-only routes check role explicitly.
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from models.models import User, LoginLog, Device, AccessLog, Alert
from extensions import db
from datetime import datetime, timedelta
from functools import wraps

dashboard_bp = Blueprint('dashboard', __name__)


# ── Admin-only decorator ─────────────────────────────────────────────────────
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin():
            flash('Administrator access required.', 'danger')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    return decorated


# ── Main Dashboard ───────────────────────────────────────────────────────────
@dashboard_bp.route('/dashboard')
@login_required
def index():
    # ── Stats cards ──────────────────────────────────────────────────────────
    devices       = Device.query.all()
    online_count  = sum(1 for d in devices if d.status == 'online')
    offline_count = sum(1 for d in devices if d.status == 'offline')

    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    failed_today = LoginLog.query.filter(
        LoginLog.success == False,
        LoginLog.timestamp >= today_start
    ).count()

    total_logs = LoginLog.query.count()

    unresolved_alerts = Alert.query.filter_by(resolved=False).order_by(Alert.timestamp.desc()).all()

    # ── Recent activity feed (last 20 login events) ───────────────────────────
    recent_logs = LoginLog.query.order_by(LoginLog.timestamp.desc()).limit(20).all()

    # ── Camera device (first camera found) ───────────────────────────────────
    camera = Device.query.filter_by(device_type='camera').first()

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
        now=datetime.utcnow()
    )


# ── User Management (admin only) ─────────────────────────────────────────────
@dashboard_bp.route('/users')
@admin_required
def users():
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template('users.html', users=all_users)


@dashboard_bp.route('/users/add', methods=['POST'])
@admin_required
def add_user():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    role     = request.form.get('role', 'viewer')

    if not username or not password:
        flash('Username and password are required.', 'danger')
        return redirect(url_for('dashboard.users'))

    if User.query.filter_by(username=username).first():
        flash(f'Username "{username}" is already taken.', 'danger')
        return redirect(url_for('dashboard.users'))

    if len(password) < 8:
        flash('Password must be at least 8 characters.', 'danger')
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
    if len(password) < 8:
        flash('New password must be at least 8 characters.', 'danger')
        return redirect(url_for('dashboard.users'))
    user.set_password(password)
    db.session.commit()
    flash(f'Password for "{user.username}" updated.', 'success')
    return redirect(url_for('dashboard.users'))


# ── Logs Page ────────────────────────────────────────────────────────────────
@dashboard_bp.route('/logs')
@login_required
def logs():
    page      = request.args.get('page', 1, type=int)
    log_type  = request.args.get('type', 'all')   # 'all' | 'failed' | 'success'

    query = LoginLog.query.order_by(LoginLog.timestamp.desc())
    if log_type == 'failed':
        query = query.filter_by(success=False)
    elif log_type == 'success':
        query = query.filter_by(success=True)

    pagination = query.paginate(page=page, per_page=50, error_out=False)
    return render_template('logs.html', pagination=pagination, log_type=log_type)


# ── Device Management (admin only) ───────────────────────────────────────────
@dashboard_bp.route('/devices/update/<int:device_id>', methods=['POST'])
@admin_required
def update_device(device_id):
    device     = Device.query.get_or_404(device_id)
    device.name       = request.form.get('name', device.name).strip()
    device.ip_address = request.form.get('ip_address', device.ip_address).strip()
    device.stream_url = request.form.get('stream_url', device.stream_url or '').strip()
    db.session.commit()
    flash(f'Device "{device.name}" updated.', 'success')
    return redirect(url_for('dashboard.index'))


# ── Resolve alert ────────────────────────────────────────────────────────────
@dashboard_bp.route('/alerts/resolve/<int:alert_id>', methods=['POST'])
@admin_required
def resolve_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.resolved = True
    db.session.commit()
    flash('Alert marked as resolved.', 'success')
    return redirect(url_for('dashboard.index'))
