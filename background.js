(() => {
  'use strict';

  const HIBP_API_BASE = 'https://haveibeenpwned.com/api/v3';

  async function sha1Hash(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }

  async function checkPasswordBreach(password) {
    try {
      const sha1 = await sha1Hash(password);
      const prefix = sha1.substring(0, 5);
      const suffix = sha1.substring(5);
      const resp = await fetch(`${HIBP_API_BASE}/breachedpassword/${prefix}`, {
        headers: { 'Add-Padding': 'true' }
      });
      if (resp.status === 404) return { breached: false, count: 0 };
      if (!resp.ok) return { breached: false, count: 0, error: `API ${resp.status}` };
      const text = await resp.text();
      const lines = text.split('\n');
      for (const line of lines) {
        const [hashSuffix, count] = line.split(':');
        if (hashSuffix.trim().toUpperCase() === suffix) {
          return { breached: true, count: parseInt(count, 10) };
        }
      }
      return { breached: false, count: 0 };
    } catch (e) {
      return { breached: false, count: 0, error: e.message };
    }
  }

  function updateBadge(breached) {
    chrome.action.setBadgeBackgroundColor({ color: breached ? '#dc3545' : '#28a745' });
    chrome.action.setBadgeText({ text: breached ? '!' : '' });
  }

  async function showBreachNotification(site, count) {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: 'Leak Guard - Password Breached!',
      message: `Your password for ${site || 'this site'} has been found in ${count.toLocaleString()} data breach${count !== 1 ? 'es' : ''}. Change it immediately!`,
      priority: 2,
      requireInteraction: true
    });
  }

  async function storePasswordHash(site, passwordHash, breached) {
    const data = await chrome.storage.local.get('passwordHistory');
    const history = data.passwordHistory || [];
    const existing = history.findIndex(e => e.site === site);
    const entry = {
      site: site || 'Unknown',
      hash: passwordHash,
      breached,
      checkedAt: Date.now(),
      lastChanged: Date.now()
    };
    if (existing >= 0) {
      history[existing] = { ...history[existing], ...entry };
    } else {
      history.push(entry);
    }
    if (history.length > 500) history.splice(0, history.length - 500);
    await chrome.storage.local.set({ passwordHistory: history });
  }

  async function getSettings() {
    const data = await chrome.storage.local.get('settings');
    return data.settings || {
      autoCheck: true,
      notifications: true,
      checkOnSave: true,
      theme: 'light',
      checkInterval: 24
    };
  }

  async function updateStatistics(key, increment = 1) {
    const data = await chrome.storage.local.get('statistics');
    const stats = data.statistics || { passwordsChecked: 0, breachesFound: 0, lastCheckDate: null };
    if (key === 'passwordsChecked') stats.passwordsChecked += increment;
    if (key === 'breachesFound') stats.breachesFound += increment;
    stats.lastCheckDate = Date.now();
    await chrome.storage.local.set({ statistics: stats });
  }

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === 'checkBreach') {
      checkPasswordBreach(msg.password).then(async result => {
        if (result.breached) {
          updateBadge(true);
          const settings = await getSettings();
          if (settings.notifications) {
            showBreachNotification(msg.site, result.count);
          }
          await updateStatistics('breachesFound');
        }
        await updateStatistics('passwordsChecked');
        await storePasswordHash(msg.site, msg.hash || '', result.breached);
        sendResponse(result);
      });
      return true;
    }

    if (msg.action === 'updateBadge') {
      updateBadge(msg.breached);
      sendResponse({ ok: true });
    }

    if (msg.action === 'getSettings') {
      getSettings().then(sendResponse);
      return true;
    }

    if (msg.action === 'saveSettings') {
      chrome.storage.local.set({ settings: msg.settings }).then(() => sendResponse({ ok: true }));
      return true;
    }

    if (msg.action === 'getStatistics') {
      chrome.storage.local.get('statistics').then(data => sendResponse(data.statistics || {
        passwordsChecked: 0, breachesFound: 0, lastCheckDate: null
      }));
      return true;
    }

    if (msg.action === 'getPasswordHistory') {
      chrome.storage.local.get('passwordHistory').then(data => {
        sendResponse(data.passwordHistory || []);
      });
      return true;
    }

    if (msg.action === 'clearHistory') {
      chrome.storage.local.set({ passwordHistory: [] }).then(() => sendResponse({ ok: true }));
      return true;
    }

    if (msg.action === 'simulateAudit') {
      chrome.storage.local.get('passwordHistory').then(data => {
        const history = data.passwordHistory || [];
        sendResponse({ history });
      });
      return true;
    }
  });

  chrome.action.setBadgeBackgroundColor({ color: '#28a745' });

  chrome.runtime.onInstalled.addListener(async () => {
    const data = await chrome.storage.local.get('settings');
    if (!data.settings) {
      await chrome.storage.local.set({
        settings: {
          autoCheck: true,
          notifications: true,
          checkOnSave: true,
          theme: 'light',
          checkInterval: 24
        },
        statistics: { passwordsChecked: 0, breachesFound: 0, lastCheckDate: null },
        passwordHistory: []
      });
    }
  });
})();
