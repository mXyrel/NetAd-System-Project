"""
extensions.py
=============
Flask extension instances live here — NOT in app.py.

This breaks the circular import chain:
  app.py → routes → models → (needs db) → app.py  ← CIRCULAR

With this file:
  app.py      → imports extensions.py (gets db, limiter, login_manager)
  models.py   → imports extensions.py (gets db)
  routes/*.py → imports extensions.py (gets db, limiter)

No circular dependency.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db            = SQLAlchemy()
login_manager = LoginManager()
limiter       = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
