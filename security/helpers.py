"""
Security Helpers — Hardened
=============================
Added:
  - sanitize_input()       — strips dangerous characters from all form inputs
  - is_strong_password()   — enforces uppercase, lowercase, digit, special char
  - is_ip_suspicious()     — checks recent fail count for an IP
  - validate_ip_address()  — validates IP format before storing/blocking
"""

import re
from models.models import LoginLog, Alert
from extensions import db
from datetime import datetime, timedelta


def sanitize_input(value: str, max_length: int = 200) -> str:
    """
    Strips leading/trailing whitespace and removes characters
    that are commonly used in injection attacks.
    This is a defense-in-depth layer — SQLAlchemy ORM already
    parameterizes queries, but this prevents dirty data entering the DB.
    """
    if not value:
        return ''
    # Strip whitespace
    value = value.strip()
    # Remove null bytes
    value = value.replace('\x00', '')
    # Truncate to max length
    value = value[:max_length]
    return value


def is_strong_password(password: str) -> tuple:
    """
    Returns (True, None) if strong, or (False, 'reason') if not.
    Rules:
      - At least 8 characters
      - At least 1 uppercase letter
      - At least 1 lowercase letter
      - At least 1 digit
      - At least 1 special character
    """
    if len(password) < 8:
        return False, 'Password must be at least 8 characters.'
    if not any(c.isupper() for c in password):
        return False, 'Password must contain at least one uppercase letter.'
    if not any(c.islower() for c in password):
        return False, 'Password must contain at least one lowercase letter.'
    if not any(c.isdigit() for c in password):
        return False, 'Password must contain at least one digit.'
    if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        return False, 'Password must contain at least one special character (!@#$%^&* etc).'
    return True, None


def is_ip_suspicious(ip: str, window_minutes: int = 60, threshold: int = 10) -> bool:
    cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
    fails  = LoginLog.query.filter(
        LoginLog.ip_address == ip,
        LoginLog.success    == False,
        LoginLog.timestamp  >= cutoff
    ).count()
    return fails >= threshold


def get_failed_attempts_today(ip: str) -> int:
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    return LoginLog.query.filter(
        LoginLog.ip_address == ip,
        LoginLog.success    == False,
        LoginLog.timestamp  >= today
    ).count()


def validate_ip_address(ip: str) -> bool:
    """Returns True if the string is a valid IPv4 or IPv6 address."""
    # IPv4
    ipv4 = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ipv4.match(ip):
        parts = ip.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    # IPv6 — basic check
    ipv6 = re.compile(r'^[0-9a-fA-F:]+$')
    return bool(ipv6.match(ip) and ':' in ip)


def maybe_raise_alert(alert_type: str, message: str, ip: str = None, severity: str = 'medium'):
    existing = Alert.query.filter_by(
        alert_type=alert_type,
        ip_address=ip,
        resolved=False
    ).first()
    if not existing:
        db.session.add(Alert(
            alert_type=alert_type,
            message=message,
            ip_address=ip,
            severity=severity
        ))
