/* PhishGuard AI - Dashboard JS */

const API_BASE = '/api';
let trendChart, distChart, typeChart;

document.addEventListener('DOMContentLoaded', () => {
  updateNavFromToken();
  loadDashboard();
  // Auto-refresh every 30s
  setInterval(loadDashboard, 30000);
});

function updateNavFromToken() {
  const token = localStorage.getItem('phishguard_token');
  const loginLink = document.getElementById('loginLink');
  const logoutLink = document.getElementById('logoutLink');
  if (token) {
    if (loginLink) loginLink.classList.add('hidden');
    if (logoutLink) logoutLink.classList.remove('hidden');
  } else {
    if (loginLink) loginLink.classList.remove('hidden');
    if (logoutLink) logoutLink.classList.add('hidden');
  }
}

function logout() {
  localStorage.removeItem('phishguard_token');
  window.location.href = '/login';
}

async function loadDashboard() {
  try {
    const token = localStorage.getItem('phishguard_token');
    const headers = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const res = await fetch(`${API_BASE}/dashboard`, { headers });
    if (!res.ok) throw new Error('Dashboard load failed');
    const data = await res.json();
    renderDashboard(data);
  } catch (err) {
    console.error('Dashboard error:', err);
  }
}

function renderDashboard(data) {
  const { stats, trend, recent_scans, attack_map, breakdown } = data;

  // Stat cards
  animateNumber('totalScans', stats.total_scans);
  animateNumber('dangerousCount', stats.dangerous);
  animateNumber('suspiciousCount', stats.suspicious);
  animateNumber('safeCount', stats.safe);

  document.getElementById('dangerousPct').textContent = `(${stats.dangerous_pct}%)`;
  document.getElementById('suspiciousPct').textContent = `(${stats.suspicious_pct}%)`;
  document.getElementById('safePct').textContent = `(${stats.safe_pct}%)`;

  // Charts
  renderTrendChart(trend);
  renderDistChart(stats);
  renderTypeChart(breakdown);

  // Recent scans
  renderRecentScans(recent_scans);

  // Attack map
  renderAttackMap(attack_map);
}

function animateNumber(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  const start = performance.now();
  const duration = 800;
  const update = (now) => {
    const p = Math.min((now - start) / duration, 1);
    const ease = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(target * ease).toLocaleString();
    if (p < 1) requestAnimationFrame(update);
  };
  requestAnimationFrame(update);
}

// ─── Chart Defaults ───────────────────────────────────────
Chart.defaults.color = '#7a9cc4';
Chart.defaults.borderColor = '#1a3a5c';
Chart.defaults.font.family = "'Share Tech Mono', monospace";

const CHART_OPTIONS = {
  responsive: true,
  maintainAspectRatio: true,
  plugins: {
    legend: { labels: { color: '#7a9cc4', boxWidth: 12, font: { size: 11 } } },
    tooltip: {
      backgroundColor: '#0a1628',
      borderColor: '#1a3a5c',
      borderWidth: 1,
      titleColor: '#e2f0ff',
      bodyColor: '#7a9cc4',
    }
  }
};

function renderTrendChart(trend) {
  const ctx = document.getElementById('trendChart');
  if (!ctx) return;
  if (trendChart) trendChart.destroy();

  const labels = (trend || []).map(d => d.date);
  const values = (trend || []).map(d => d.count);

  trendChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Scans',
        data: values,
        borderColor: '#00d4ff',
        backgroundColor: 'rgba(0,212,255,0.08)',
        borderWidth: 2,
        pointBackgroundColor: '#00d4ff',
        pointRadius: 4,
        fill: true,
        tension: 0.4
      }]
    },
    options: {
      ...CHART_OPTIONS,
      scales: {
        x: { grid: { color: 'rgba(26,58,92,0.5)' }, ticks: { color: '#7a9cc4', font: { size: 10 } } },
        y: { grid: { color: 'rgba(26,58,92,0.5)' }, ticks: { color: '#7a9cc4', font: { size: 10 } }, beginAtZero: true }
      }
    }
  });
}

function renderDistChart(stats) {
  const ctx = document.getElementById('distChart');
  if (!ctx) return;
  if (distChart) distChart.destroy();

  distChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Safe', 'Suspicious', 'Dangerous'],
      datasets: [{
        data: [stats.safe || 0, stats.suspicious || 0, stats.dangerous || 0],
        backgroundColor: ['rgba(0,255,136,0.6)', 'rgba(255,214,10,0.6)', 'rgba(255,51,88,0.6)'],
        borderColor: ['#00ff88', '#ffd60a', '#ff3358'],
        borderWidth: 2,
        hoverOffset: 8
      }]
    },
    options: {
      ...CHART_OPTIONS,
      cutout: '65%',
      plugins: {
        ...CHART_OPTIONS.plugins,
        legend: { position: 'bottom', labels: { color: '#7a9cc4', boxWidth: 10, font: { size: 10 } } }
      }
    }
  });
}

function renderTypeChart(breakdown) {
  const ctx = document.getElementById('typeChart');
  if (!ctx) return;
  if (typeChart) typeChart.destroy();

  typeChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['URLs', 'Messages'],
      datasets: [{
        label: 'Scans',
        data: [breakdown?.url_scans || 0, breakdown?.text_scans || 0],
        backgroundColor: ['rgba(0,212,255,0.4)', 'rgba(168,85,247,0.4)'],
        borderColor: ['#00d4ff', '#a855f7'],
        borderWidth: 2,
        borderRadius: 6,
      }]
    },
    options: {
      ...CHART_OPTIONS,
      scales: {
        x: { grid: { display: false }, ticks: { color: '#7a9cc4' } },
        y: { grid: { color: 'rgba(26,58,92,0.5)' }, ticks: { color: '#7a9cc4' }, beginAtZero: true }
      },
      plugins: { ...CHART_OPTIONS.plugins, legend: { display: false } }
    }
  });
}

function renderRecentScans(scans) {
  const container = document.getElementById('recentScansList');
  if (!container) return;

  if (!scans || scans.length === 0) {
    container.innerHTML = '<div class="loading-state">No scans yet. Start scanning!</div>';
    return;
  }

  container.innerHTML = scans.map(scan => {
    const scoreColor = scan.risk_score >= 60 ? '#ff3358' : scan.risk_score >= 30 ? '#ffd60a' : '#00ff88';
    const cls = (scan.classification || 'safe').toLowerCase();
    const time = new Date(scan.timestamp).toLocaleTimeString();
    return `
      <div class="scan-row">
        <span class="scan-row-score" style="color:${scoreColor}">${Math.round(scan.risk_score)}</span>
        <span class="badge ${cls}">${scan.classification}</span>
        <span class="scan-row-input">${escapeHtml(scan.input_text)}</span>
        <span class="scan-row-time">${time}</span>
      </div>
    `;
  }).join('');
}

function renderAttackMap(events) {
  const container = document.getElementById('attackMap');
  if (!container) return;

  if (!events || events.length === 0) {
    container.innerHTML = '<div class="map-loading">No threat events detected yet.</div>';
    return;
  }

  // Simulated live threat feed display
  container.innerHTML = '';

  const header = document.createElement('div');
  header.style.cssText = 'display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;';
  header.innerHTML = `
    <span style="font-family:var(--font-mono);font-size:11px;color:var(--accent-cyan);letter-spacing:1px;">LIVE THREAT FEED</span>
    <span style="font-family:var(--font-mono);font-size:10px;color:var(--text-dim);">${events.length} events</span>
  `;
  container.appendChild(header);

  events.forEach((event, i) => {
    const div = document.createElement('div');
    div.className = `attack-event ${event.classification.toLowerCase()}`;
    div.style.animationDelay = `${i * 0.1}s`;

    const icon = event.classification === 'Dangerous' ? '🚨' : '⚠️';
    const type = event.type === 'url' ? '🔗' : '✉️';
    const time = new Date(event.timestamp).toLocaleTimeString();

    div.innerHTML = `
      <span>${icon}</span>
      <span>${type}</span>
      <span style="flex:1;color:var(--text-secondary);font-size:11px;">Score: <strong style="color:${event.classification === 'Dangerous' ? '#ff3358' : '#ffd60a'}">${Math.round(event.risk_score)}</strong></span>
      <span style="font-family:var(--font-mono);font-size:10px;color:var(--text-dim);">${time}</span>
    `;
    container.appendChild(div);
  });

  // Add random new event simulation
  simulateNewThreats(container);
}

function simulateNewThreats(container) {
  // Add a pulsing "live" indicator
  const liveDiv = document.createElement('div');
  liveDiv.style.cssText = 'display:flex;align-items:center;gap:6px;margin-top:10px;padding:6px;';
  liveDiv.innerHTML = `
    <span class="pulse-dot" style="background:var(--accent-green)"></span>
    <span style="font-family:var(--font-mono);font-size:10px;color:var(--text-dim)">Monitoring active...</span>
  `;
  container.appendChild(liveDiv);
}

function escapeHtml(text) {
  return (text || '').toString()
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}
