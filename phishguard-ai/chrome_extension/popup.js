/* PhishGuard AI - Chrome Extension Popup JS */

const API_URL = 'http://localhost:5000/api/scan';

document.addEventListener('DOMContentLoaded', async () => {
  // Get current tab URL
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tabs[0]?.url || '';
  document.getElementById('currentUrl').textContent = url || 'No URL';

  // Load auto-scan preference
  const prefs = await chrome.storage.local.get(['autoScan']);
  document.getElementById('autoScanToggle').checked = prefs.autoScan || false;

  // Check if we have a cached result for this URL
  const cache = await chrome.storage.local.get([`result_${url}`]);
  if (cache[`result_${url}`]) {
    showResult(cache[`result_${url}`]);
  }
});

async function scanCurrentPage() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tabs[0]?.url || '';

  if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://')) {
    return;
  }

  const btn = document.getElementById('scanBtn');
  btn.disabled = true;
  btn.textContent = '⏳ Scanning...';
  document.getElementById('loadingSection').style.display = 'block';
  document.getElementById('resultSection').style.display = 'none';

  try {
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input: url, mode: 'fast' })
    });

    if (!response.ok) throw new Error('API error');

    const data = await response.json();

    // Cache result
    await chrome.storage.local.set({ [`result_${url}`]: data });

    // Update badge
    updateBadge(data.risk_score);

    // Show dangerous page warning
    if (data.risk_score >= 60) {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: '🚨 PhishGuard AI Warning',
        message: `DANGEROUS: ${url.substring(0, 60)}\nRisk Score: ${Math.round(data.risk_score)}/100`
      });
    }

    showResult(data);

  } catch (err) {
    document.getElementById('currentUrl').textContent = '❌ Could not connect to PhishGuard server. Make sure it\'s running on localhost:5000';
  } finally {
    btn.disabled = false;
    btn.textContent = '🔍 SCAN THIS PAGE';
    document.getElementById('loadingSection').style.display = 'none';
  }
}

function showResult(data) {
  document.getElementById('resultSection').style.display = 'block';

  const score = Math.round(data.risk_score || 0);
  const cls = data.classification || {};
  const cssClass = cls.css_class || 'safe';

  document.getElementById('riskNum').textContent = score;

  const badge = document.getElementById('riskBadge');
  badge.textContent = `${cls.emoji || ''} ${cls.label || 'Unknown'}`;
  badge.className = `risk-badge ${cssClass}`;

  const fill = document.getElementById('riskFill');
  fill.className = `risk-fill ${cssClass}`;
  setTimeout(() => { fill.style.width = score + '%'; }, 50);

  // Rules
  const rulesEl = document.getElementById('rulesList');
  rulesEl.innerHTML = (data.triggered_rules || []).slice(0, 3)
    .map(r => `<div class="rule">${r}</div>`).join('');

  // Actions
  const actionsEl = document.getElementById('actionBtns');
  if (score >= 60) {
    actionsEl.innerHTML = `
      <button class="action-btn block" onclick="blockPage()">🚫 Block</button>
      <button class="action-btn open" onclick="openFullScanner()">🔍 Details</button>
    `;
  } else {
    actionsEl.innerHTML = `
      <button class="action-btn open" onclick="openFullScanner()">📊 Full Report</button>
    `;
  }
}

function updateBadge(score) {
  const color = score >= 60 ? '#FF3358' : score >= 30 ? '#FFD60A' : '#00FF88';
  const text = score >= 60 ? '!!!' : score >= 30 ? '?' : '✓';
  chrome.action.setBadgeBackgroundColor({ color });
  chrome.action.setBadgeText({ text });
}

async function blockPage() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  chrome.tabs.update(tabs[0].id, {
    url: 'chrome-extension://' + chrome.runtime.id + '/blocked.html'
  });
}

function openFullScanner() {
  chrome.tabs.create({ url: 'http://localhost:5000' });
}

async function toggleAutoScan() {
  const enabled = document.getElementById('autoScanToggle').checked;
  await chrome.storage.local.set({ autoScan: enabled });
}
