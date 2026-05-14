"""
API Routes
==========
JSON endpoints consumed by dashboard.js for live updates.
All endpoints require authentication.

GET  /api/devices/status    — ping all devices, return JSON status
GET  /api/stats             — summary numbers for the stats cards
GET  /api/logs/recent       — last 10 login events
GET  /api/alerts            — unresolved alerts
POST /api/devices/<id>/ping — force a single device ping
"""

import subprocess
import platform
from flask import Blueprint, jsonify, request
from flask_login import login_required, current_user
from models.models import Device, LoginLog, Alert, AccessLog
from extensions import db
from datetime import datetime, timedelta

api_bp = Blueprint('api', __name__)


# ── Helper: Ping a device ────────────────────────────────────────────────────
def ping_device(ip_address: str) -> bool:
    """
    Returns True if the device responds to ICMP ping.
    Works on both Linux (Railway) and Windows (local dev).
    """
    if not ip_address:
        return False
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    cmd   = ['ping', param, '1', '-W', '1', ip_address]
    try:
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        return result.returncode == 0
    except Exception:
        return False


# ── Ping all devices, update DB, return JSON ─────────────────────────────────
@api_bp.route('/devices/status', methods=['GET'])
@login_required
def devices_status():
    devices = Device.query.all()
    output  = []

    for dev in devices:
        old_status = dev.status
        is_up      = ping_device(dev.ip_address)
        new_status = 'online' if is_up else 'offline'

        dev.status       = new_status
        dev.last_checked = datetime.utcnow()
        if is_up:
            dev.last_seen = datetime.utcnow()

        # Log the check
        log = AccessLog(
            device_id=dev.id,
            device_name=dev.name,
            ip_address=dev.ip_address,
            action='ping_check',
            initiated_by='system',
            result=new_status
        )
        db.session.add(log)

        # If device just went offline, raise an alert
        if old_status == 'online' and new_status == 'offline':
            alert = Alert(
                alert_type='device_offline',
                message=f'{dev.name} ({dev.ip_address}) went offline.',
                ip_address=dev.ip_address,
                severity='high'
            )
            db.session.add(alert)

        output.append({
            'id':           dev.id,
            'name':         dev.name,
            'type':         dev.device_type,
            'ip':           dev.ip_address,
            'status':       dev.status,
            'last_seen':    dev.last_seen.isoformat() if dev.last_seen else None,
            'last_checked': dev.last_checked.isoformat() if dev.last_checked else None,
        })

    db.session.commit()
    return jsonify({'devices': output, 'checked_at': datetime.utcnow().isoformat()})


# ── Force ping a single device ───────────────────────────────────────────────
@api_bp.route('/devices/<int:device_id>/ping', methods=['POST'])
@login_required
def ping_single(device_id):
    dev   = Device.query.get_or_404(device_id)
    is_up = ping_device(dev.ip_address)

    dev.status       = 'online' if is_up else 'offline'
    dev.last_checked = datetime.utcnow()
    if is_up:
        dev.last_seen = datetime.utcnow()

    log = AccessLog(
        device_id=dev.id,
        device_name=dev.name,
        ip_address=dev.ip_address,
        action='manual_ping',
        initiated_by=current_user.username,
        result=dev.status
    )
    db.session.add(log)
    db.session.commit()

    return jsonify({'id': dev.id, 'name': dev.name, 'status': dev.status})


# ── Summary stats ────────────────────────────────────────────────────────────
@api_bp.route('/stats', methods=['GET'])
@login_required
def stats():
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    return jsonify({
        'devices_online':     Device.query.filter_by(status='online').count(),
        'devices_offline':    Device.query.filter_by(status='offline').count(),
        'failed_logins_today':LoginLog.query.filter(LoginLog.success == False, LoginLog.timestamp >= today_start).count(),
        'total_logs':         LoginLog.query.count(),
        'unresolved_alerts':  Alert.query.filter_by(resolved=False).count(),
    })


# ── Recent login logs (last 10) ───────────────────────────────────────────────
@api_bp.route('/logs/recent', methods=['GET'])
@login_required
def recent_logs():
    logs = LoginLog.query.order_by(LoginLog.timestamp.desc()).limit(10).all()
    return jsonify({'logs': [
        {
            'id':       l.id,
            'username': l.username_attempted,
            'ip':       l.ip_address,
            'success':  l.success,
            'action':   l.action,
            'time':     l.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        }
        for l in logs
    ]})


# ── Unresolved alerts ────────────────────────────────────────────────────────
@api_bp.route('/alerts', methods=['GET'])
@login_required
def alerts():
    items = Alert.query.filter_by(resolved=False).order_by(Alert.timestamp.desc()).limit(20).all()
    return jsonify({'alerts': [
        {
            'id':        a.id,
            'type':      a.alert_type,
            'message':   a.message,
            'severity':  a.severity,
            'ip':        a.ip_address,
            'time':      a.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        }
        for a in items
    ]})
