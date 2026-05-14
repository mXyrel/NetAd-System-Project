/**
 * Group 8 — Dashboard JS
 * =======================
 * Handles:
 *  - Live clock in the top bar
 *  - Auto-refresh of device statuses via /api/devices/status
 *  - Auto-refresh of log feed via /api/logs/recent
 *  - Auto-refresh of stats via /api/stats
 *  - Manual single-device ping via /api/devices/<id>/ping
 *  - Sidebar toggle
 */

'use strict';

// ── Clock ────────────────────────────────────────────────────────────────────
function updateTopClock() {
  const el = document.getElementById('top-clock');
  if (!el) return;
  const now = new Date();
  el.textContent = now.toLocaleString('en-US', {
    weekday: 'short', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
  });
}

setInterval(updateTopClock, 1000);
updateTopClock();


// ── Sidebar toggle ───────────────────────────────────────────────────────────
function toggleSidebar() {
  const sb = document.getElementById('sidebar');
  if (window.innerWidth <= 768) {
    sb.classList.toggle('open');
  } else {
    sb.classList.toggle('collapsed');
    document.querySelector('.main-content').style.marginLeft =
      sb.classList.contains('collapsed') ? '0' : 'var(--sidebar-w)';
  }
}


// ── Fetch helper (returns null on error instead of throwing) ─────────────────
async function apiFetch(url, options = {}) {
  try {
    const res = await fetch(url, { credentials: 'same-origin', ...options });
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    console.warn('[Group 8] API error:', url, e);
    return null;
  }
}


// ── Update stats cards ───────────────────────────────────────────────────────
async function refreshStats() {
  const data = await apiFetch('/api/stats');
  if (!data) return;

  setNum('stat-online',  data.devices_online);
  setNum('stat-offline', data.devices_offline);
  setNum('stat-failed',  data.failed_logins_today);
  setNum('stat-total',   data.total_logs);
}

function setNum(id, val) {
  const el = document.getElementById(id);
  if (el && el.textContent !== String(val)) {
    el.textContent = val;
    el.classList.add('updated');
    setTimeout(() => el.classList.remove('updated'), 600);
  }
}


// ── Update device status cards ───────────────────────────────────────────────
async function refreshDevices() {
  const refreshIcon = document.getElementById('refresh-icon');
  if (refreshIcon) refreshIcon.classList.add('spinning');

  const data = await apiFetch('/api/devices/status');

  if (refreshIcon) refreshIcon.classList.remove('spinning');
  if (!data || !data.devices) return;

  data.devices.forEach(dev => {
    // Status text badge
    const statusEl = document.getElementById(`status-${dev.id}`);
    if (statusEl) {
      statusEl.className = `device-status ${dev.status}`;
      const dot = statusEl.querySelector('.status-dot') || document.createElement('span');
      dot.className = `status-dot ${dev.status}`;
      const label = document.createTextNode(' ' + capitalize(dev.status));
      statusEl.innerHTML = '';
      statusEl.appendChild(dot);
      statusEl.appendChild(label);
    }

    // Device icon wrap (color changes with status)
    const card = document.getElementById(`device-${dev.id}`);
    if (card) {
      const iconWrap = card.querySelector('.device-icon-wrap');
      if (iconWrap) {
        iconWrap.className = `device-icon-wrap ${dev.status}`;
      }
    }
  });
}


// ── Ping a single device (manual button) ────────────────────────────────────
async function pingSingle(deviceId, btn) {
  const originalHTML = btn.innerHTML;
  btn.innerHTML = '<i class="bi bi-arrow-repeat spinning"></i>';
  btn.disabled  = true;

  const data = await apiFetch(`/api/devices/${deviceId}/ping`, { method: 'POST' });

  btn.innerHTML = originalHTML;
  btn.disabled  = false;

  if (!data) return;

  // Flash green or red based on result
  const card = document.getElementById(`device-${deviceId}`);
  if (card) {
    card.style.transition = 'background 0.3s';
    card.style.background = data.status === 'online'
      ? 'rgba(0,230,118,0.08)'
      : 'rgba(255,82,82,0.08)';
    setTimeout(() => { card.style.background = ''; }, 1000);
  }

  // Update status label immediately
  const statusEl = document.getElementById(`status-${deviceId}`);
  if (statusEl) {
    statusEl.className = `device-status ${data.status}`;
    statusEl.innerHTML = `<span class="status-dot ${data.status}"></span> ${capitalize(data.status)}`;
  }
}


// ── Refresh log table ────────────────────────────────────────────────────────
async function refreshLogs() {
  const data = await apiFetch('/api/logs/recent');
  if (!data || !data.logs) return;

  const tbody = document.getElementById('log-tbody');
  if (!tbody) return;

  const rows = data.logs.map(log => `
    <tr class="${log.success ? 'row-ok' : 'row-fail'}">
      <td class="td-time">${log.time.split(' ')[1]}</td>
      <td><i class="bi bi-person text-muted me-1"></i>${escapeHTML(log.username)}</td>
      <td><code>${escapeHTML(log.ip)}</code></td>
      <td>${capitalize(log.action)}</td>
      <td>
        ${log.success
          ? '<span class="badge-ok"><i class="bi bi-check-circle me-1"></i>Success</span>'
          : '<span class="badge-fail"><i class="bi bi-x-circle me-1"></i>Failed</span>'}
      </td>
    </tr>
  `).join('');

  tbody.innerHTML = rows || '<tr><td colspan="5" class="text-center text-muted py-3">No entries yet.</td></tr>';
}


// ── Force full refresh (button) ───────────────────────────────────────────────
async function forceRefresh() {
  await Promise.all([refreshDevices(), refreshStats(), refreshLogs()]);
}


// ── Utility ──────────────────────────────────────────────────────────────────
function capitalize(str) {
  return str ? str.charAt(0).toUpperCase() + str.slice(1) : '';
}

function escapeHTML(str) {
  const d = document.createElement('div');
  d.appendChild(document.createTextNode(str || ''));
  return d.innerHTML;
}

function cameraError() {
  const img = document.getElementById('camera-stream');
  if (img) {
    img.style.display = 'none';
    const vp = img.parentElement;
    if (vp) {
      vp.innerHTML = `
        <div class="camera-placeholder">
          <i class="bi bi-camera-video-off"></i>
          <p>Camera stream unavailable</p>
          <p class="cam-ip">Check the stream URL or device status</p>
        </div>`;
    }
  }
}


// ── Auto-refresh schedule ────────────────────────────────────────────────────
// Devices: every 30 seconds
// Logs:    every 10 seconds
// Stats:   every 10 seconds

setInterval(refreshDevices, 30000);
setInterval(refreshLogs,    10000);
setInterval(refreshStats,   10000);

// Initial load on page ready
document.addEventListener('DOMContentLoaded', () => {
  forceRefresh();
});
