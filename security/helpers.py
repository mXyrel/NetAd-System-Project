"""
Security Helpers
================
Utility functions for security checks used across the app.

Usage:
    from security.helpers import is_ip_suspicious, log_unauthorized_attempt
"""

from models.models import LoginLog, Alert
from extensions import db
from datetime import datetime, timedelta


# ── Suspicious IP detection ──────────────────────────────────────────────────
def is_ip_suspicious(ip: str, window_minutes: int = 60, threshold: int = 10) -> bool:
    """
    Returns True if an IP has more than `threshold` failed logins
    within the last `window_minutes` minutes.
    """
    cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
    fails  = LoginLog.query.filter(
        LoginLog.ip_address == ip,
        LoginLog.success    == False,
        LoginLog.timestamp  >= cutoff
    ).count()
    return fails >= threshold


def get_failed_attempts_today(ip: str) -> int:
    """Returns the number of failed login attempts from an IP today."""
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    return LoginLog.query.filter(
        LoginLog.ip_address == ip,
        LoginLog.success    == False,
        LoginLog.timestamp  >= today
    ).count()


# ── Raise alert if needed ────────────────────────────────────────────────────
def maybe_raise_alert(alert_type: str, message: str, ip: str = None, severity: str = 'medium'):
    """
    Creates an Alert only if no identical unresolved alert exists for the same IP.
    Prevents alert flooding.
    """
    existing = Alert.query.filter_by(
        alert_type=alert_type,
        ip_address=ip,
        resolved=False
    ).first()
    if not existing:
        alert = Alert(
            alert_type=alert_type,
            message=message,
            ip_address=ip,
            severity=severity
        )
        db.session.add(alert)
        # commit is expected to happen in the calling route


# ── Password strength check ──────────────────────────────────────────────────
def is_strong_password(password: str) -> tuple:
    """
    Returns (True, None) if password is strong enough,
    or (False, 'reason') if not.
    Minimum: 8 chars, 1 uppercase, 1 lowercase, 1 digit.
    """
    if len(password) < 8:
        return False, 'Password must be at least 8 characters.'
    if not any(c.isupper() for c in password):
        return False, 'Password must contain at least one uppercase letter.'
    if not any(c.islower() for c in password):
        return False, 'Password must contain at least one lowercase letter.'
    if not any(c.isdigit() for c in password):
        return False, 'Password must contain at least one digit.'
    return True, None
