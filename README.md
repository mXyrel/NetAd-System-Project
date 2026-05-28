# Group 8 — Network Hardware Monitoring & Protection System

A Flask-based web security and monitoring system for network hardware (IP Camera, Router, Switch).
Stores persistent logs in PostgreSQL. Deployed live on Railway. Security hardened against penetration testing.

**GitHub Repository:** https://github.com/mXyrel/NetAd-System-Project
**Live URL:** https://netad-system-project-production.up.railway.app 

---

## Table of Contents

1. [Project Structure](#project-structure)
2. [Local Development Setup](#local-development-setup)
3. [Running the App Locally](#running-the-app-locally)
4. [GitHub Workflow](#github-workflow)
5. [Railway Deployment](#railway-deployment)
6. [PostgreSQL Database](#postgresql-database)
7. [Environment Variables](#environment-variables)
8. [Connecting Your IP Camera](#connecting-your-ip-camera)
9. [Connecting Router & Switch](#connecting-router--switch)
10. [Default Login Credentials](#default-login-credentials)
11. [User Management](#user-management)
12. [IP Blocking Management](#ip-blocking-management)
13. [Security Features](#security-features)
14. [Database — Managing Logs & Data](#database--managing-logs--data)
15. [How Logs Persist After Redeployment](#how-logs-persist-after-redeployment)
16. [Troubleshooting](#troubleshooting)
17. [Quick Reference](#quick-reference)
18. [Team Responsibilities](#team-responsibilities)

---

## Project Structure

```
network-monitor/
│
├── app.py                  ← Main Flask app factory + security headers + migrations
├── extensions.py           ← db, login_manager, limiter (avoids circular imports)
├── requirements.txt        ← Python dependencies
├── Procfile                ← Tells Railway/Gunicorn how to run the app
├── railway.toml            ← Railway deployment configuration
├── .env.example            ← Template — copy to .env for local dev
├── .gitignore              ← Keeps .env and secrets off GitHub
│
├── models/
│   └── models.py           ← All database tables:
│                              User, LoginLog, Device, AccessLog, Alert, BlockedIP
│
├── routes/
│   ├── auth.py             ← Login / logout + CSRF + brute-force + IP block check
│   ├── dashboard.py        ← Dashboard, user management, IP blocking, device editing
│   └── api.py              ← JSON API for live device pings and stats
│
├── security/
│   └── helpers.py          ← Input sanitization, password strength, IP validation
│
├── templates/
│   ├── base.html           ← Base HTML layout (Bootstrap 5 dark theme)
│   ├── login.html          ← Login page with CSRF token
│   ├── dashboard.html      ← Main monitoring dashboard + webcam/IP cam toggle
│   ├── logs.html           ← Full audit log with pagination and filters
│   └── users.html          ← User management + IP blocking panel (admin only)
│
└── static/
    ├── css/style.css       ← Full custom dark security aesthetic
    └── js/dashboard.js     ← Live update logic (ping, log refresh, clock)
```

---

## Local Development Setup

### Step 1 — Clone the repository

```bash
git clone https://github.com/mXyrel/NetAd-System-Project.git
cd NetAd-System-Project
```

### Step 2 — Create a virtual environment

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Create your .env file

```bash
# Windows
copy .env.example .env

# macOS / Linux
cp .env.example .env
```

Open `.env` and set:

```env
SECRET_KEY=any-long-random-string-here-change-this
DATABASE_URL=sqlite:///monitor.db
ADMIN_PASSWORD=YourSecurePassword123!
FLASK_ENV=development
FLASK_DEBUG=false
```

> **Note:** SQLite works perfectly for local development.
> PostgreSQL is only required on Railway (production).

---

## Running the App Locally

```bash
python app.py
```

Then open your browser to: **http://127.0.0.1:5000**

On first run, the system automatically:
- Creates all database tables
- Runs column migrations on existing databases (safe — never deletes data)
- Creates the default `admin` account using `ADMIN_PASSWORD` from `.env`
- Creates the three default devices (Camera, Router, Switch)

To stop the app: press `Ctrl + C` in the terminal.

---

## GitHub Workflow

**Repository:** https://github.com/mXyrel/NetAd-System-Project

### Pushing changes

```bash
# Check what changed (verify .env is NOT listed)
git status

# Stage files
git add .

# Commit with a message
git commit -m "your message here"

# Push to GitHub (Railway auto-deploys after this)
git push
```

### If push is rejected (remote has changes you don't have)

```bash
git config pull.rebase false
git pull origin main
# Close any merge message file that opens, then:
git push
```

### Important before every push

Run `git status` and confirm `.env` is **not** in the list. If it appears, your credentials would be exposed publicly. The `.gitignore` file should be blocking it.

---

## Railway Deployment

The project is already deployed. Railway auto-deploys every time you push to GitHub. No manual steps needed for updates.

**To check deployment status:**
1. Go to https://railway.app
2. Open the **talented-friendship** project (the main live deployment)
3. Click the **Deployments** tab
4. Wait for the green ✅ Active status

**If a deployment fails:**
1. Click the failed deployment
2. Read the Deploy Logs for the exact error
3. Most common causes: missing environment variable, PostgreSQL migration error

---

## PostgreSQL Database

The PostgreSQL database is already set up on Railway as a separate service. It runs independently from the app and is never affected by redeployments.

**Railway auto-provides** the `DATABASE_URL` variable — you never need to set this manually.

### Automatic Migrations

The app runs `_run_migrations()` on every startup. This safely adds new columns to existing tables without deleting any data. You will see `[MIGRATION]` lines in Railway logs the first time after a schema change — this is normal and expected.

---

## Environment Variables

These must be set in Railway → your app service → **Variables tab**.

| Variable         | Value                         | Notes                                      |
|------------------|-------------------------------|--------------------------------------------|
| `SECRET_KEY`     | random 32+ char string        | Generate with command below. Required.     |
| `ADMIN_PASSWORD` | your admin password           | Used on first boot only to create admin    |
| `FLASK_ENV`      | `production`                  | Enables HTTPS cookies, HSTS header         |
| `FLASK_DEBUG`    | `false`                       | Never set true in production               |
| `DATABASE_URL`   | (auto-set by Railway)         | Do not touch — Railway fills this in       |

**Generate a SECRET_KEY:**

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

> **Important:** The app will refuse to start in production if `SECRET_KEY` is
> missing or set to the default value. This is intentional security behavior.

---

## Connecting Your IP Camera

The dashboard supports two camera modes toggled by buttons:

- **Webcam** — uses the laptop/device's built-in camera via browser
- **IP Cam** — connects to a network camera via its stream URL (button only appears when configured)
- **Turn Off** — stops whichever camera is active

### Setting up an IP camera

1. Connect the camera to the same WiFi as your laptop
2. Find its IP address:
   ```bash
   arp -a
   ```
   Look for a new IP in the list — that's the camera. Your network is `192.168.18.x`.

3. Open that IP in your browser to confirm it loads a camera web interface
4. Find the stream URL inside the camera's settings page
5. Log in to the dashboard as admin
6. Click the **pencil edit** button on IP Camera 01
7. Set the **IP Address** and **Stream URL**, then save
8. The **IP Cam** button will appear in the camera panel

### Common stream URL formats by brand

| Brand       | Stream URL Format                                                   |
|-------------|---------------------------------------------------------------------|
| Generic     | `http://192.168.18.x/video.mjpg`                                    |
| Hikvision   | `http://192.168.18.x/ISAPI/Streaming/channels/101/picture`          |
| Dahua       | `http://192.168.18.x/cgi-bin/snapshot.cgi`                          |
| D-Link      | `http://192.168.18.x/video.cgi`                                     |
| Reolink     | `http://192.168.18.x/cgi-bin/api.cgi?cmd=Snap&channel=0&user=admin&password=PASS` |

> **Note:** Camera streaming only works when running locally (`python app.py`)
> on the same network as the camera. The Railway-deployed version cannot reach
> a camera on your home/school network.

### RTSP cameras (Tapo, modern Reolink, etc.)

RTSP streams cannot be embedded directly in a browser. Use a JPEG snapshot URL instead,
or run an RTSP-to-MJPEG proxy using ffmpeg:

```bash
ffmpeg -rtsp_transport tcp -i rtsp://admin:password@192.168.18.x:554/stream1 \
  -f mjpeg -q:v 5 http://localhost:8090/feed
```

---

## Connecting Router & Switch

Devices are monitored by ICMP ping — the same as typing `ping 192.168.18.1` in a terminal.

### Update the IP addresses to your real network

Your network is `192.168.18.x`. The defaults are wrong. Update them:

1. Log in as admin
2. Click the **pencil edit** button on each device card
3. Set the correct IP:

| Device         | Your correct IP  |
|----------------|-----------------|
| Main Router    | `192.168.18.1`  |
| Network Switch | find via `arp -a` |
| IP Camera 01   | find via `arp -a` |

4. Click **Save** — the device will immediately attempt a ping

---

## Default Login Credentials

```
Username: admin
Password: Admin@1234!   (or whatever you set as ADMIN_PASSWORD)
```

> Change this immediately after first login via Users → key icon → Change Password.

---

## User Management

Access at `/users` — admin accounts only. Viewer accounts are blocked from this page.

| Action          | How                                              |
|-----------------|--------------------------------------------------|
| Add a user      | Fill in the Add User form on the right           |
| Delete a user   | Click the 🗑 trash icon                          |
| Change password | Click the 🔑 key icon                            |
| Unlock account  | Click the 🔓 unlock icon (appears when locked)   |
| View status     | Status column shows Active or Locked             |

**Password requirements (enforced server-side):**
- Minimum 8 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 digit
- At least 1 special character (`!@#$%^&*` etc.)

**Recommended group setup:**

| Member    | Username  | Role   |
|-----------|-----------|--------|
| Lead      | `admin`   | admin  |
| Member 2  | `member2` | viewer |
| Member 3  | `member3` | viewer |
| Member 4  | `member4` | viewer |

---

## IP Blocking Management

Access at `/users` (bottom section) — admin only.

### Manual block
1. Enter an IP address in the Block an IP form
2. Add a reason (optional)
3. Click **Block IP** — the IP is permanently blocked until manually unblocked

### Automatic block
The system automatically blocks an IP after **15 failed login attempts in 1 hour**.
A critical alert is raised and the block expires after 24 hours.

### Unblock
Click the **Unblock** button next to any IP in the Blocked IP Addresses table.

---

## Security Features

### Full security layer list

| Feature                    | File                   | How it works                                              |
|----------------------------|------------------------|-----------------------------------------------------------|
| Password hashing           | `models/models.py`     | PBKDF2-SHA256 via werkzeug — never stored plain text      |
| Account lockout            | `models/models.py`     | 5 failed logins = 15 min lock, shown in Users page        |
| Login delay                | `routes/auth.py`       | 0.5s artificial delay on every failed attempt             |
| CSRF protection            | `routes/auth.py`       | Hidden token validated on every POST request              |
| IP block check             | `routes/auth.py`       | Blocked IPs rejected before any DB query runs             |
| Brute-force alert          | `routes/auth.py`       | 5 fails/10min from same IP → critical alert               |
| Auto IP block              | `routes/auth.py`       | 15 fails/1hr → automatic 24hr block + critical alert      |
| Constant-time comparison   | `routes/auth.py`       | Prevents timing attacks on user enumeration               |
| New IP login alert         | `routes/auth.py`       | Admin login from new IP → high severity alert             |
| Session fingerprinting     | `app.py`               | Browser fingerprint checked every request — detects hijack|
| HTTPS redirect             | `app.py`               | HTTP requests force-redirected to HTTPS in production     |
| Security headers           | `app.py`               | X-Frame-Options, CSP, HSTS, X-XSS-Protection, Referrer   |
| Server version hidden      | `app.py`               | Server and X-Powered-By headers removed from responses    |
| SECRET_KEY validation      | `app.py`               | App refuses to start in production without valid key      |
| Protected routes           | `routes/dashboard.py`  | `@login_required` on every dashboard route                |
| Admin-only routes          | `routes/dashboard.py`  | `@admin_required` + unauthorized attempt logged as alert  |
| Input sanitization         | `security/helpers.py`  | All form inputs stripped of injection characters          |
| Rate limiting              | `extensions.py`        | 20 login attempts/min per IP via Flask-Limiter            |
| Open-redirect blocked      | `routes/auth.py`       | `next` param only accepted if it starts with `/`          |

### What the professor will test — and the result

| Attack                              | Result                                                     |
|-------------------------------------|------------------------------------------------------------|
| Access `/dashboard` without login   | Redirected to login — `@login_required`                    |
| Access `/users` as viewer           | Blocked + alert logged — `@admin_required`                 |
| Brute force login                   | Locked after 5 fails, IP blocked after 15, rate limited    |
| SQL injection in login form         | Blocked — SQLAlchemy ORM + input sanitization              |
| CSRF form submission                | Blocked — token mismatch returns error                     |
| Steal session cookie, use elsewhere | Blocked — browser fingerprint mismatch forces logout       |
| Look for credentials in GitHub      | Not there — `.gitignore` blocks `.env`                     |
| Check logs after redeploy           | All logs still there — PostgreSQL is separate from app     |
| Find SECRET_KEY in code             | Not there — only exists in Railway environment variables   |
| Access API endpoints without login  | Blocked — all `/api/` routes have `@login_required`        |

---

## Database — Managing Logs & Data

### Viewing data on Railway

1. Go to Railway → your PostgreSQL service
2. Click the **Data** tab to browse tables visually
3. Or use the **Query** tab to run SQL directly

### Deleting logs (if needed)

To clear all login logs directly in PostgreSQL:

```sql
-- Delete all login logs
DELETE FROM login_logs;

-- Delete only failed login logs
DELETE FROM login_logs WHERE success = false;

-- Delete logs older than 30 days
DELETE FROM login_logs WHERE timestamp < NOW() - INTERVAL '30 days';

-- Delete all alerts
DELETE FROM alerts;

-- Delete all access logs
DELETE FROM access_logs;
```

> Run these in Railway → PostgreSQL service → **Query** tab.
> This is permanent and cannot be undone. The app continues running normally
> after deleting rows — no restart needed.

### Unlocking a locked account via SQL (emergency)

If you get locked out and can't access the Users page:

```sql
UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE username = 'admin';
```

### Removing a blocked IP via SQL (emergency)

```sql
DELETE FROM blocked_ips WHERE ip_address = '1.2.3.4';
```

---

## How Logs Persist After Redeployment

This is the core architectural guarantee of the system.

```
Your Flask App (Railway container)   →   writes logs   →   PostgreSQL (separate Railway service)
                                                                  ↑
                                    This database is NEVER touched by redeployment.
                                    Logs from week 1 are still there in week 10.
                                    Pushing new code only restarts the Flask app.
```

**What gets logged permanently:**
- Every login attempt (success or failure) — IP, timestamp, username, browser, failure reason
- Every logout
- Every device ping check result
- Every security alert (brute force, device offline, IP blocked, CSRF violation, session hijack)

---

## Troubleshooting

### App won't start locally

```bash
# Activate virtual environment first
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS/Linux

# Reinstall dependencies
pip install -r requirements.txt

# Run the app
python app.py
```

### "No module named flask" or similar

Your virtual environment is not active. Run `venv\Scripts\activate` first.

### "No module named psycopg2"

```bash
pip install psycopg2-binary --break-system-packages
```

### Railway deployment fails

1. Click the failed deployment in Railway → read the Deploy Logs
2. Most common causes:
   - `SECRET_KEY` not set in Railway variables → app refuses to start in production
   - PostgreSQL migration error → check for `[MIGRATION]` error lines in logs
   - Missing `Procfile` in GitHub repo

### Migration error on Railway (DATETIME vs TIMESTAMP)

Already fixed in the current `app.py`. The migration function auto-detects PostgreSQL
and uses `TIMESTAMP` instead of `DATETIME`. If you see old migration errors in logs,
they are from a previous version and can be ignored as long as the app starts.

### Camera not showing

1. Make sure you're running locally with `python app.py`
2. Camera and laptop must be on the same WiFi network
3. Test the stream URL directly in your browser first
4. The Webcam button uses your laptop's built-in camera — no network needed

### Login keeps redirecting to login page

`SECRET_KEY` is changing between requests. Set it as a fixed string in Railway variables.

### Account locked out

Go to Users page → click the 🔓 unlock button next to the account.
Or via SQL: `UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE username = 'admin';`

### Push rejected by GitHub

```bash
git config pull.rebase false
git pull origin main
git push
```

---

## Quick Reference

```bash
# Run locally
python app.py

# Open in browser
http://127.0.0.1:5000

# Activate virtual environment (Windows)
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Generate a SECRET_KEY
python -c "import secrets; print(secrets.token_hex(32))"

# Push to GitHub (triggers Railway auto-deploy)
git add .
git commit -m "your message"
git push

# Pull before push (if rejected)
git pull origin main

# Check Railway logs
# railway.app → talented-friendship project → Deployments tab → Deploy Logs
```

---

## Team Responsibilities

| Role              | Main files                                      |
|-------------------|-------------------------------------------------|
| Backend / Lead    | `app.py`, `extensions.py`, `routes/`            |
| Database Manager  | `models/models.py`, Railway PostgreSQL setup    |
| Security Lead     | `security/helpers.py`, `routes/auth.py`         |
| UI / Frontend     | `templates/`, `static/css/style.css`            |

---

*Group 8 — Network Hardware Monitoring & Protection System*
*Built with Flask, PostgreSQL, Railway*
*GitHub: https://github.com/mXyrel/NetAd-System-Project*
