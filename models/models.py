"""
Database Models — Security Hardened
=====================================
Added to User model:
  - failed_login_count  → tracks consecutive failures
  - locked_until        → account lockout timestamp
  - last_ip             → last known IP that logged in
  - must_change_password → force password change on next login
"""

from extensions import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id                   = db.Column(db.Integer, primary_key=True)
    username             = db.Column(db.String(80),  unique=True, nullable=False, index=True)
    password_hash        = db.Column(db.String(256), nullable=False)
    role                 = db.Column(db.String(20),  default='viewer')
    created_at           = db.Column(db.DateTime,    default=datetime.utcnow)
    last_login           = db.Column(db.DateTime,    nullable=True)
    last_ip              = db.Column(db.String(45),  nullable=True)
    is_active            = db.Column(db.Boolean,     default=True)

    # ── Lockout fields ───────────────────────────────────────────────────────
    failed_login_count   = db.Column(db.Integer,  default=0)
    locked_until         = db.Column(db.DateTime, nullable=True)
    must_change_password = db.Column(db.Boolean,  default=False)

    login_logs = db.relationship('LoginLog', backref='user', lazy='dynamic')

    # ── Password methods ─────────────────────────────────────────────────────
    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    # ── Lockout methods ──────────────────────────────────────────────────────
    def is_locked(self) -> bool:
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        if self.locked_until and self.locked_until <= datetime.utcnow():
            # Lock expired — auto-reset
            self.locked_until = None
            self.failed_login_count = 0
        return False

    def lock_minutes_remaining(self) -> int:
        if self.locked_until and self.locked_until > datetime.utcnow():
            delta = self.locked_until - datetime.utcnow()
            return max(1, int(delta.total_seconds() / 60))
        return 0

    def record_failed_login(self):
        self.failed_login_count += 1
        if self.failed_login_count >= 5:
            self.locked_until = datetime.utcnow() + timedelta(minutes=15)

    def record_successful_login(self):
        self.failed_login_count = 0
        self.locked_until = None

    def is_admin(self) -> bool:
        return self.role == 'admin'

    def __repr__(self):
        return f'<User {self.username} [{self.role}]>'


class LoginLog(db.Model):
    __tablename__ = 'login_logs'

    id                 = db.Column(db.Integer, primary_key=True)
    user_id            = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username_attempted = db.Column(db.String(80))
    ip_address         = db.Column(db.String(45))
    user_agent         = db.Column(db.String(512))
    timestamp          = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    success            = db.Column(db.Boolean,  default=False)
    action             = db.Column(db.String(20), default='login')
    failure_reason     = db.Column(db.String(50), nullable=True)  # 'bad_password'|'locked'|'inactive'

    def __repr__(self):
        return f'<LoginLog {self.username_attempted} {"OK" if self.success else "FAIL"} @ {self.ip_address}>'


class Device(db.Model):
    __tablename__ = 'devices'

    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(100), nullable=False)
    device_type = db.Column(db.String(50))
    ip_address  = db.Column(db.String(45))
    stream_url  = db.Column(db.String(512), nullable=True)
    status      = db.Column(db.String(20),  default='unknown')
    last_seen   = db.Column(db.DateTime,    nullable=True)
    last_checked= db.Column(db.DateTime,    nullable=True)
    added_by    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    access_logs = db.relationship('AccessLog', backref='device', lazy='dynamic')

    def status_badge(self):
        return {'online': 'success', 'offline': 'danger', 'unknown': 'secondary'}.get(self.status, 'secondary')

    def __repr__(self):
        return f'<Device {self.name} [{self.ip_address}] {self.status}>'


class AccessLog(db.Model):
    __tablename__ = 'access_logs'

    id           = db.Column(db.Integer, primary_key=True)
    device_id    = db.Column(db.Integer, db.ForeignKey('devices.id'), nullable=True)
    device_name  = db.Column(db.String(100))
    ip_address   = db.Column(db.String(45))
    action       = db.Column(db.String(100))
    timestamp    = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    initiated_by = db.Column(db.String(80))
    result       = db.Column(db.String(20))

    def __repr__(self):
        return f'<AccessLog {self.device_name} {self.action} {self.result}>'


class Alert(db.Model):
    __tablename__ = 'alerts'

    id         = db.Column(db.Integer, primary_key=True)
    alert_type = db.Column(db.String(60))
    message    = db.Column(db.String(512))
    ip_address = db.Column(db.String(45),  nullable=True)
    timestamp  = db.Column(db.DateTime,    default=datetime.utcnow, index=True)
    resolved   = db.Column(db.Boolean,     default=False)
    severity   = db.Column(db.String(20),  default='medium')

    def severity_badge(self):
        return {'low': 'info', 'medium': 'warning', 'high': 'danger', 'critical': 'danger'}.get(self.severity, 'secondary')

    def __repr__(self):
        return f'<Alert [{self.severity}] {self.alert_type}>'


class BlockedIP(db.Model):
    """
    Permanently or temporarily blocked IP addresses.
    The login route checks this table before processing any attempt.
    """
    __tablename__ = 'blocked_ips'

    id         = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    reason     = db.Column(db.String(256))
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    blocked_by = db.Column(db.String(80))             # username who blocked it, or 'system'
    expires_at = db.Column(db.DateTime, nullable=True) # None = permanent

    def is_active(self) -> bool:
        if self.expires_at is None:
            return True
        return self.expires_at > datetime.utcnow()

    def __repr__(self):
        return f'<BlockedIP {self.ip_address}>'
