/* PhishGuard AI - Background Service Worker */

const API_URL = 'http://localhost:5000/api/scan';

// Listen for tab updates (auto-scan)
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  if (!tab.url || tab.url.startsWith('chrome://')) return;

  // Check auto-scan preference
  const prefs = await chrome.storage.local.get(['autoScan']);
  if (!prefs.autoScan) return;

  try {
    const response = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input: tab.url, mode: 'fast' })
    });

    if (!response.ok) return;
    const data = await response.json();

    const score = data.risk_score || 0;
    const color = score >= 60 ? '#FF3358' : score >= 30 ? '#FFD60A' : '#00FF88';
    const text = score >= 60 ? '!!!' : score >= 30 ? '?' : '✓';

    chrome.action.setBadgeBackgroundColor({ color, tabId });
    chrome.action.setBadgeText({ text, tabId });

    // Block dangerous pages
    if (score >= 80) {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: '🚨 PhishGuard AI - DANGER',
        message: `Blocked dangerous page!\nRisk: ${Math.round(score)}/100\n${tab.url.substring(0, 80)}`
      });
    }

  } catch (e) {
    // Server not running - fail silently
  }
});

// Message handler from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'scanUrl') {
    fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input: request.url, mode: 'fast' })
    })
    .then(r => r.json())
    .then(data => sendResponse({ success: true, data }))
    .catch(err => sendResponse({ success: false, error: err.message }));
    return true; // Async response
  }
});
