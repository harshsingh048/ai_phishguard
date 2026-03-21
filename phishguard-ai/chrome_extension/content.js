/* PhishGuard AI - Content Script */
/* Runs on every page to highlight suspicious links */

(function() {
  'use strict';

  const PHISHING_INDICATORS = [
    /paypa[l1]/i, /amaz0n/i, /g00gle/i, /micros0ft/i, /app[l1]e/i,
    /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/,  // IP address in URL
    /\.xyz$|\.tk$|\.ml$|\.ga$|\.cf$|\.top$/i,
  ];

  function checkLink(href) {
    return PHISHING_INDICATORS.some(pattern => pattern.test(href));
  }

  function addWarningBadge(link) {
    if (link.dataset.phishguardChecked) return;
    link.dataset.phishguardChecked = '1';

    if (checkLink(link.href)) {
      link.style.outline = '2px solid #ff3358';
      link.style.outlineOffset = '2px';
      link.title = '⚠️ PhishGuard AI: This link looks suspicious!';

      const badge = document.createElement('span');
      badge.textContent = '⚠️';
      badge.style.cssText = `
        display: inline-block; font-size: 12px; cursor: help;
        margin-left: 3px; vertical-align: middle;
      `;
      badge.title = 'PhishGuard AI: Suspicious link detected';
      link.insertAdjacentElement('afterend', badge);
    }
  }

  // Scan all links on load
  function scanLinks() {
    document.querySelectorAll('a[href]').forEach(link => {
      try {
        if (link.href && link.href.startsWith('http')) {
          addWarningBadge(link);
        }
      } catch(e) {}
    });
  }

  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', scanLinks);
  } else {
    scanLinks();
  }

  // Watch for dynamically added links
  const observer = new MutationObserver(mutations => {
    mutations.forEach(mutation => {
      mutation.addedNodes.forEach(node => {
        if (node.nodeType === 1) {
          if (node.tagName === 'A') addWarningBadge(node);
          node.querySelectorAll && node.querySelectorAll('a[href]').forEach(addWarningBadge);
        }
      });
    });
  });

  observer.observe(document.body, { childList: true, subtree: true });

})();
