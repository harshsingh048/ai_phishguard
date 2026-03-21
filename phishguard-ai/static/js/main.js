/* PhishGuard AI - Main Scanner JS */

const API_BASE = '/api';
let currentMode = 'fast';
let lastResult = null;

const EXAMPLES = {
  phishing_url: 'http://paypa1-verify.com/login?redirect=evil.com&token=abc123&verify=true',
  safe_url: 'https://www.github.com/features/copilot',
  spam_msg: 'URGENT: Your PayPal account has been suspended due to suspicious activity. Click here IMMEDIATELY to verify your identity and avoid permanent account closure: http://paypa1-secure.xyz/verify?id=8473',
  legit_msg: 'Hi Sarah, just following up on our project meeting from Tuesday. Could you send me the final report by Thursday EOD? Let me know if you need anything. Thanks!'
};

// ─── Init ────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  updateNavFromToken();
  const input = document.getElementById('scanInput');
  if (input) {
    input.addEventListener('keydown', (e) => {
      if (e.ctrlKey && e.key === 'Enter') runScan();
    });
  }
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

// ─── Mode ────────────────────────────────────────────────
function setMode(mode) {
  currentMode = mode;
  document.getElementById('fastBtn').classList.toggle('active', mode === 'fast');
  document.getElementById('deepBtn').classList.toggle('active', mode === 'deep');
}

// ─── Input ───────────────────────────────────────────────
function onInputChange(el) {
  const val = el.value;
  document.getElementById('charCount').textContent = `${val.length} / 5000`;
  const badge = document.getElementById('inputTypeBadge');
  const type = detectInputType(val.trim());
  badge.textContent = val.trim() === '' ? 'AUTO-DETECT' :
    type === 'url' ? '🔗 URL' : '✉️ MESSAGE';
}

function detectInputType(text) {
  if (!text) return 'unknown';
  if (/^https?:\/\//i.test(text)) return 'url';
  if (/^www\./i.test(text)) return 'url';
  if (/^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(\/|$)/.test(text) && !text.includes(' ')) return 'url';
  return 'text';
}

function loadExample(type) {
  const input = document.getElementById('scanInput');
  input.value = EXAMPLES[type];
  onInputChange(input);
  input.focus();
}

function handleEnter(e) {
  if (e.key === 'Enter' && e.ctrlKey) runScan();
}

// ─── Scan ────────────────────────────────────────────────
async function runScan() {
  const input = document.getElementById('scanInput').value.trim();
  if (!input) {
    showToast('⚠️ Please enter a URL or message to scan', 'error');
    return;
  }

  setScanLoading(true);
  hideResults();

  try {
    const token = localStorage.getItem('phishguard_token');
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const res = await fetch(`${API_BASE}/scan`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ input, mode: currentMode })
    });

    const data = await res.json();

    if (!res.ok) {
      showToast('❌ ' + (data.error || 'Scan failed'), 'error');
      return;
    }

    lastResult = data;
    renderResults(data);

  } catch (err) {
    showToast('❌ Connection error. Is the server running?', 'error');
    console.error(err);
  } finally {
    setScanLoading(false);
  }
}

function setScanLoading(loading) {
  const btn = document.getElementById('scanBtn');
  const content = document.getElementById('btnContent');
  const loadingEl = document.getElementById('btnLoading');
  const textarea = document.getElementById('scanInput');

  btn.disabled = loading;
  content.classList.toggle('hidden', loading);
  loadingEl.classList.toggle('hidden', !loading);
  textarea.disabled = loading;

  if (loading && currentMode === 'deep') {
    let step = 0;
    const steps = ['Analyzing features...', 'Running ML model...', 'WHOIS lookup...', 'Threat intelligence...', 'Deep analysis...'];
    const interval = setInterval(() => {
      if (!loading) { clearInterval(interval); return; }
      document.getElementById('loadingText').textContent = steps[step % steps.length];
      step++;
    }, 800);
    btn._loadingInterval = interval;
  } else if (!loading && btn._loadingInterval) {
    clearInterval(btn._loadingInterval);
  }
}

// ─── Render Results ───────────────────────────────────────
function renderResults(data) {
  const panel = document.getElementById('resultsPanel');
  panel.classList.remove('hidden');

  const score = data.risk_score || 0;
  const cls = data.classification || {};
  const cssClass = cls.css_class || 'safe';

  // Risk score
  animateNumber('riskScore', 0, Math.round(score), 800);
  document.getElementById('riskEmoji').textContent = cls.emoji || '?';
  document.getElementById('riskLabel').textContent = cls.label || 'Unknown';

  const badge = document.getElementById('riskBadge');
  badge.className = `risk-badge ${cssClass}`;

  const bar = document.getElementById('riskBarFill');
  bar.className = `risk-bar-fill ${cssClass}`;
  setTimeout(() => { bar.style.width = score + '%'; }, 50);

  document.getElementById('riskDescription').textContent = cls.description || '';

  // Meta
  document.getElementById('scanMode').textContent = `Mode: ${(data.mode || 'fast').toUpperCase()}`;
  document.getElementById('scanType').textContent = `Type: ${(data.input_type || '?').toUpperCase()}`;
  document.getElementById('scanTime').textContent = `Time: ${data.response_time_ms || 0}ms`;

  const cacheEl = document.getElementById('cacheIndicator');
  if (data.from_cache) cacheEl.classList.remove('hidden');
  else cacheEl.classList.add('hidden');

  // Explanation
  document.getElementById('explanationText').textContent = data.explanation || 'Analysis complete.';

  const rulesContainer = document.getElementById('triggeredRules');
  rulesContainer.innerHTML = '';
  (data.triggered_rules || []).forEach(rule => {
    const div = document.createElement('div');
    div.className = 'rule-item';
    div.textContent = rule;
    rulesContainer.appendChild(div);
  });

  // Suggestions
  const sugList = document.getElementById('suggestionsList');
  sugList.innerHTML = '';
  (data.suggestions || []).forEach(sug => {
    const div = document.createElement('div');
    div.className = `suggestion-item ${sug.priority || 'info'}`;
    div.innerHTML = `<span>${sug.icon || '•'}</span><span>${sug.action}</span>`;
    sugList.appendChild(div);
  });

  // URL Breakdown
  const urlCard = document.getElementById('urlHighlightCard');
  const textCard = document.getElementById('textHighlightCard');

  if (data.input_type === 'url' && data.url_highlights) {
    urlCard.classList.remove('hidden');
    textCard.classList.add('hidden');
    renderUrlBreakdown(data.url_highlights);
  } else if (data.input_type === 'text') {
    textCard.classList.remove('hidden');
    urlCard.classList.add('hidden');
    renderHighlightedText(data.input, data.text_highlights || []);
  }

  // ML Scores
  renderMLScores(data.ml_scores || {}, score);

  // Scroll to results
  setTimeout(() => panel.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
}

function renderUrlBreakdown(highlights) {
  const container = document.getElementById('urlBreakdown');
  container.innerHTML = '';
  Object.entries(highlights).forEach(([key, val]) => {
    if (!val || !val.text) return;
    const span = document.createElement('span');
    span.className = `url-part ${val.risk || 'low'}`;
    span.textContent = val.text;
    span.title = `${key.toUpperCase()}: ${val.risk} risk`;
    container.appendChild(span);
  });
}

function renderHighlightedText(text, highlights) {
  const container = document.getElementById('highlightedText');
  if (!highlights || highlights.length === 0) {
    container.textContent = text;
    return;
  }

  // Build highlighted HTML
  let html = '';
  let lastIdx = 0;
  const sorted = [...highlights].sort((a, b) => a.start - b.start);

  sorted.forEach(span => {
    if (span.start > lastIdx) {
      html += escapeHtml(text.slice(lastIdx, span.start));
    }
    html += `<mark class="${span.category}">${escapeHtml(text.slice(span.start, span.end))}</mark>`;
    lastIdx = span.end;
  });

  html += escapeHtml(text.slice(lastIdx));
  container.innerHTML = html;
}

function renderMLScores(scores, finalScore) {
  const container = document.getElementById('mlScores');
  container.innerHTML = '';

  const engines = [
    { label: 'ML Model', value: scores.ml_score, color: '#4da6ff', available: scores.ml_available },
    { label: 'Rule Engine', value: scores.rule_score, color: '#ffd60a', available: true },
    { label: 'BERT (Deep)', value: scores.bert_score, color: '#a855f7', available: scores.bert_score !== null },
    { label: 'Final Score', value: finalScore, color: finalScore >= 60 ? '#ff3358' : finalScore >= 30 ? '#ffd60a' : '#00ff88', available: true },
  ];

  engines.forEach(engine => {
    if (!engine.available && engine.value === null) return;
    const val = engine.value !== null && engine.value !== undefined ? Math.round(engine.value) : null;

    const div = document.createElement('div');
    div.className = 'ml-score-item';
    div.innerHTML = `
      <span class="ml-score-label">${engine.label}</span>
      <div class="ml-score-bar-wrap">
        <div class="ml-score-bar" style="width:0%; background:${engine.color}20; border: 1px solid ${engine.color}40" data-target="${val || 0}" data-color="${engine.color}"></div>
      </div>
      <span class="ml-score-val">${val !== null ? val + '/100' : 'N/A'}</span>
    `;
    container.appendChild(div);
  });

  // Animate bars
  setTimeout(() => {
    container.querySelectorAll('.ml-score-bar').forEach(bar => {
      const target = bar.dataset.target;
      const color = bar.dataset.color;
      bar.style.transition = 'width 0.8s ease';
      bar.style.width = target + '%';
      bar.style.background = color + '30';
      bar.style.borderColor = color + '60';
    });
  }, 100);
}

function hideResults() {
  document.getElementById('resultsPanel').classList.add('hidden');
}

function newScan() {
  document.getElementById('scanInput').value = '';
  document.getElementById('charCount').textContent = '0 / 5000';
  document.getElementById('inputTypeBadge').textContent = 'AUTO-DETECT';
  hideResults();
  document.getElementById('scanInput').focus();
}

// ─── Export ───────────────────────────────────────────────
async function exportJSON() {
  if (!lastResult) { showToast('No scan result to export', 'error'); return; }

  try {
    const res = await fetch(`${API_BASE}/report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'json', scan_result: lastResult })
    });
    const data = await res.json();
    if (data.success) {
      // Also download in browser
      const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'phishguard_report.json'; a.click();
      showToast('✅ JSON report downloaded!', 'success');
    }
  } catch (err) {
    // Fallback: direct browser download
    const blob = new Blob([JSON.stringify(lastResult, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'phishguard_report.json'; a.click();
    showToast('✅ JSON report downloaded!', 'success');
  }
}

async function copyResult() {
  if (!lastResult) { showToast('No result to copy', 'error'); return; }
  const summary = `PhishGuard AI Scan Result
Input: ${lastResult.input}
Risk Score: ${lastResult.risk_score}/100
Classification: ${lastResult.classification?.label}
Explanation: ${lastResult.explanation}
Triggered: ${(lastResult.triggered_rules || []).join('; ')}`;
  try {
    await navigator.clipboard.writeText(summary);
    showToast('📋 Copied to clipboard!', 'success');
  } catch (e) {
    showToast('❌ Copy failed', 'error');
  }
}

// ─── Utilities ────────────────────────────────────────────
function animateNumber(id, from, to, duration) {
  const el = document.getElementById(id);
  if (!el) return;
  const start = performance.now();
  const update = (now) => {
    const p = Math.min((now - start) / duration, 1);
    const ease = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(from + (to - from) * ease);
    if (p < 1) requestAnimationFrame(update);
  };
  requestAnimationFrame(update);
}

function escapeHtml(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function showToast(msg, type = 'info') {
  const toast = document.getElementById('toast');
  if (!toast) return;
  toast.textContent = msg;
  toast.className = `toast ${type}`;
  toast.classList.remove('hidden');
  clearTimeout(toast._timeout);
  toast._timeout = setTimeout(() => toast.classList.add('hidden'), 3500);
}
