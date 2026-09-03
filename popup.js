(() => {
  'use strict';

  const $ = sel => document.querySelector(sel);
  const $$ = sel => document.querySelectorAll(sel);

  function initTabs() {
    $$('.lg-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        $$('.lg-tab').forEach(t => t.classList.remove('active'));
        $$('.lg-panel').forEach(p => p.classList.remove('active'));
        tab.classList.add('active');
        $(`#panel-${tab.dataset.tab}`).classList.add('active');
      });
    });
  }

  function initTheme() {
    chrome.storage.local.get('settings', data => {
      const theme = data.settings?.theme || 'light';
      document.documentElement.setAttribute('data-theme', theme);
    });

    $('#themeToggle').addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme');
      const next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      chrome.storage.local.get('settings', data => {
        const settings = data.settings || {};
        settings.theme = next;
        chrome.storage.local.set({ settings });
      });
    });
  }

  async function sha1Hash(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }

  async function checkBreach(password) {
    try {
      const sha1 = await sha1Hash(password);
      const prefix = sha1.substring(0, 5);
      const suffix = sha1.substring(5);
      const resp = await fetch(`https://haveibeenpwned.com/api/v3/breachedpassword/${prefix}`, {
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

  function calcStrength(pw) {
    if (!pw) return { score: 0, label: 'None', color: '#ccc', entropy: 0, details: [] };
    const details = [];
    let score = 0;
    const len = pw.length;
    let cs = 0;
    if (/[a-z]/.test(pw)) cs += 26;
    if (/[A-Z]/.test(pw)) cs += 26;
    if (/[0-9]/.test(pw)) cs += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) cs += 32;
    const entropy = len * Math.log2(Math.max(cs, 1));
    score += Math.min(30, len * 2);
    score += Math.min(30, entropy / 2);
    if (/[a-z]/.test(pw)) { score += 5; details.push('Lowercase'); }
    if (/[A-Z]/.test(pw)) { score += 5; details.push('Uppercase'); }
    if (/[0-9]/.test(pw)) { score += 5; details.push('Numbers'); }
    if (/[^a-zA-Z0-9]/.test(pw)) { score += 10; details.push('Symbols'); }
    if (/(.)\1{2,}/.test(pw)) { score -= 10; details.push('Repeating chars'); }
    if (/^(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|qwe|asd|zxc)/i.test(pw)) {
      score -= 15; details.push('Sequential pattern');
    }
    score = Math.max(0, Math.min(100, score));
    let label, color;
    if (score < 25) { label = 'Very Weak'; color = '#dc3545'; }
    else if (score < 45) { label = 'Weak'; color = '#fd7e14'; }
    else if (score < 65) { label = 'Fair'; color = '#ffc107'; }
    else if (score < 85) { label = 'Strong'; color = '#20c997'; }
    else { label = 'Very Strong'; color = '#28a745'; }
    return { score, label, color, entropy: Math.round(entropy), details };
  }

  function renderStrength(container, strength) {
    container.style.display = 'block';
    container.innerHTML = `
      <div class="lg-strength-bar-outer">
        <div class="lg-strength-bar-inner" style="width:${strength.score}%;background:${strength.color}"></div>
      </div>
      <div class="lg-strength-label" style="color:${strength.color}">${strength.label} (${strength.score}/100)</div>
      <div class="lg-strength-entropy">Entropy: ${strength.entropy} bits</div>
      ${strength.details.length ? `<div class="lg-strength-details">${strength.details.map(d => `<span>${d}</span>`).join('')}</div>` : ''}
    `;
  }

  function initCheck() {
    const input = $('#checkInput');
    const result = $('#checkResult');
    const strength = $('#strengthDisplay');
    const btn = $('#checkBtn');

    input.addEventListener('input', () => {
      const pw = input.value;
      if (pw) {
        renderStrength(strength, calcStrength(pw));
      } else {
        strength.style.display = 'none';
      }
    });

    $('#toggleCheckVisibility').addEventListener('click', () => {
      input.type = input.type === 'password' ? 'text' : 'password';
    });

    btn.addEventListener('click', async () => {
      const pw = input.value.trim();
      if (!pw) { result.style.display = 'block'; result.className = 'lg-result lg-result-info'; result.textContent = 'Please enter a password.'; return; }

      btn.disabled = true;
      btn.innerHTML = '<svg class="spin" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg> Checking...';
      result.style.display = 'block';
      result.className = 'lg-result lg-result-info';
      result.textContent = 'Checking password against known breaches...';

      const breach = await checkBreach(pw);
      const str = calcStrength(pw);

      if (breach.error) {
        result.className = 'lg-result lg-result-error';
        result.innerHTML = `<strong>Error:</strong> ${breach.error}`;
      } else if (breach.breached) {
        result.className = 'lg-result lg-result-breached';
        result.innerHTML = `
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:4px">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          <strong>BREACHED!</strong> This password was found in <strong>${breach.count.toLocaleString()}</strong> data breach${breach.count !== 1 ? 'es' : ''}. Change it immediately!
        `;
        chrome.runtime.sendMessage({ action: 'updateBadge', breached: true });
      } else {
        result.className = 'lg-result lg-result-safe';
        result.innerHTML = `
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:4px">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
          </svg>
          <strong>Safe!</strong> This password was not found in any known data breaches.
        `;
      }

      chrome.runtime.sendMessage({
        action: 'checkBreach',
        password: pw,
        hash: await sha1Hash(pw)
      });

      btn.disabled = false;
      btn.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg> Check for Breaches';
      updateStats();
    });
  }

  function initGenerator() {
    const lengthSlider = $('#genLength');
    const lengthVal = $('#genLengthVal');
    const output = $('#genOutput');
    const strengthDisp = $('#genStrength');

    lengthSlider.addEventListener('input', () => {
      lengthVal.textContent = lengthSlider.value;
      generate();
    });

    ['genUpper', 'genLower', 'genDigits', 'genSymbols'].forEach(id => {
      $(`#${id}`).addEventListener('change', generate);
    });

    function generate() {
      const len = parseInt(lengthSlider.value);
      const useUpper = $('#genUpper').checked;
      const useLower = $('#genLower').checked;
      const useDigits = $('#genDigits').checked;
      const useSymbols = $('#genSymbols').checked;

      let chars = '';
      if (useUpper) chars += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      if (useLower) chars += 'abcdefghijklmnopqrstuvwxyz';
      if (useDigits) chars += '0123456789';
      if (useSymbols) chars += '!@#$%^&*()-_=+[]{}|;:,.<>?';
      if (!chars) chars = 'abcdefghijklmnopqrstuvwxyz';

      const arr = new Uint32Array(len);
      crypto.getRandomValues(arr);
      let pw = '';
      for (let i = 0; i < len; i++) pw += chars[arr[i] % chars.length];

      output.value = pw;
      renderStrength(strengthDisp, calcStrength(pw));
    }

    $('#genGenerateBtn').addEventListener('click', generate);
    generate();

    $('#genCopyBtn').addEventListener('click', () => {
      navigator.clipboard.writeText(output.value).then(() => {
        const btn = $('#genCopyBtn');
        btn.innerHTML = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#28a745" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>';
        setTimeout(() => {
          btn.innerHTML = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
        }, 1500);
      });
    });
  }

  function initAudit() {
    $('#runAuditBtn').addEventListener('click', async () => {
      const input = $('#auditInput').value.trim();
      if (!input) return;
      const passwords = input.split('\n').map(p => p.trim()).filter(p => p);
      if (passwords.length === 0) return;

      const results = [];
      for (const pw of passwords) {
        const breach = await checkBreach(pw);
        const str = calcStrength(pw);
        const weakCheck = window.LeakGuardAudit.checkWeakPassword(pw);
        results.push({
          password: pw.substring(0, 3) + '*'.repeat(Math.max(0, pw.length - 3)),
          strength: str,
          breach,
          weak: weakCheck
        });
      }

      const weakCount = results.filter(r => r.weak.weak).length;
      const breachCount = results.filter(r => r.breach.breached).length;
      const totalCount = results.length;
      const score = Math.max(0, 100 - (weakCount * 15) - (breachCount * 20));
      let grade = 'F';
      if (score >= 90) grade = 'A+';
      else if (score >= 80) grade = 'A';
      else if (score >= 70) grade = 'B';
      else if (score >= 60) grade = 'C';
      else if (score >= 40) grade = 'D';

      const gradeColor = score >= 80 ? 'var(--success)' : score >= 60 ? 'var(--warning)' : 'var(--danger)';

      let html = `
        <div class="lg-card">
          <div class="lg-audit-score">
            <div class="lg-audit-grade" style="color:${gradeColor}">${grade}</div>
            <div class="lg-audit-score-label">Security Score: ${score}/100</div>
          </div>
          <div class="lg-stats-grid" style="margin-bottom:12px">
            <div class="lg-stat"><span class="lg-stat-value">${totalCount}</span><span class="lg-stat-label">Total</span></div>
            <div class="lg-stat"><span class="lg-stat-value lg-stat-danger">${weakCount}</span><span class="lg-stat-label">Weak</span></div>
            <div class="lg-stat"><span class="lg-stat-value lg-stat-danger">${breachCount}</span><span class="lg-stat-label">Breached</span></div>
          </div>
      `;

      if (breachCount > 0) {
        html += '<div class="lg-audit-section"><div class="lg-audit-section-title" style="color:var(--danger)">Breached Passwords</div>';
        results.filter(r => r.breach.breached).forEach(r => {
          html += `<div class="lg-audit-item lg-audit-item-critical">${r.password} - Found in ${r.breach.count.toLocaleString()} breaches</div>`;
        });
        html += '</div>';
      }

      if (weakCount > 0) {
        html += '<div class="lg-audit-section"><div class="lg-audit-section-title" style="color:var(--warning)">Weak Passwords</div>';
        results.filter(r => r.weak.weak).forEach(r => {
          const issues = r.weak.issues.filter(i => i.severity !== 'info').map(i => i.message).join('; ');
          html += `<div class="lg-audit-item lg-audit-item-warning">${r.password} - ${issues}</div>`;
        });
        html += '</div>';
      }

      const strong = results.filter(r => !r.weak.weak && !r.breach.breached);
      if (strong.length > 0) {
        html += '<div class="lg-audit-section"><div class="lg-audit-section-title" style="color:var(--success)">Strong Passwords</div>';
        strong.forEach(r => {
          html += `<div class="lg-audit-item" style="border-left:3px solid var(--success)">${r.password} - Score: ${r.strength.score}/100</div>`;
        });
        html += '</div>';
      }

      html += '</div>';
      $('#auditResults').innerHTML = html;
      $('#auditResults').style.display = 'block';
    });
  }

  function initHistory() {
    loadHistory();
    $('#clearHistoryBtn').addEventListener('click', () => {
      if (confirm('Clear all breach history?')) {
        chrome.runtime.sendMessage({ action: 'clearHistory' }, () => loadHistory());
      }
    });
  }

  function loadHistory() {
    chrome.runtime.sendMessage({ action: 'getPasswordHistory' }, history => {
      const list = $('#historyList');
      if (!history || history.length === 0) {
        list.innerHTML = '<div class="lg-empty-state">No passwords checked yet.</div>';
        return;
      }
      list.innerHTML = history.map(item => {
        const date = new Date(item.checkedAt).toLocaleDateString();
        const badge = item.breached
          ? '<span class="lg-history-badge lg-badge-breached">Breached</span>'
          : '<span class="lg-history-badge lg-badge-safe">Safe</span>';
        return `
          <div class="lg-history-item">
            <div>
              <div class="lg-history-site">${escapeHtml(item.site)}</div>
              <div class="lg-history-meta">Checked: ${date}</div>
            </div>
            ${badge}
          </div>
        `;
      }).join('');
    });
  }

  function initSettings() {
    chrome.storage.local.get('settings', data => {
      const s = data.settings || {};
      $('#settingAutoCheck').checked = s.autoCheck !== false;
      $('#settingNotifications').checked = s.notifications !== false;
      $('#settingCheckOnSave').checked = s.checkOnSave !== false;
      $('#settingTheme').value = s.theme || 'light';
      $('#settingInterval').value = String(s.checkInterval || 24);
    });

    $('#settingsBtn').addEventListener('click', () => {
      $$('.lg-tab').forEach(t => t.classList.remove('active'));
      $$('.lg-panel').forEach(p => p.classList.remove('active'));
      $('#panel-settings').classList.add('active');
    });

    $('#saveSettingsBtn').addEventListener('click', () => {
      const settings = {
        autoCheck: $('#settingAutoCheck').checked,
        notifications: $('#settingNotifications').checked,
        checkOnSave: $('#settingCheckOnSave').checked,
        theme: $('#settingTheme').value,
        checkInterval: parseInt($('#settingInterval').value)
      };
      document.documentElement.setAttribute('data-theme', settings.theme);
      chrome.runtime.sendMessage({ action: 'saveSettings', settings }, () => {
        const btn = $('#saveSettingsBtn');
        btn.textContent = 'Saved!';
        btn.style.background = 'var(--success)';
        setTimeout(() => { btn.textContent = 'Save Settings'; btn.style.background = ''; }, 1500);
      });
    });
  }

  function initNews() {
    loadBreachNews();
  }

  async function loadBreachNews() {
    const feed = $('#newsFeed');
    try {
      const resp = await fetch('https://haveibeenpwned.com/api/v3/breaches', {
        headers: { 'user-agent': 'LeakGuard-Extension/1.0' }
      });
      if (!resp.ok) throw new Error('API error');
      const breaches = await resp.json();
      feed.innerHTML = breaches.slice(0, 15).map(b => {
        const date = new Date(b.BreachDate).toLocaleDateString();
        const desc = escapeHtml(b.Description || '').substring(0, 120);
        return `
          <div class="lg-news-item" onclick="window.open('https://haveibeenpwned.com/Breach/${escapeHtml(b.Name)}','_blank')">
            <div class="lg-news-title">${escapeHtml(b.Title)}</div>
            <div class="lg-news-meta">${date} &middot; ${b.PwnCount.toLocaleString()} accounts &middot; ${escapeHtml(b.DataClasses?.join(', ') || 'Unknown')}</div>
            <div class="lg-news-desc">${desc}...</div>
          </div>
        `;
      }).join('');
    } catch (e) {
      feed.innerHTML = '<div class="lg-empty-state">Unable to load breach data. Please try again later.</div>';
    }
  }

  function updateStats() {
    chrome.runtime.sendMessage({ action: 'getStatistics' }, stats => {
      if (!stats) return;
      $('#statChecked').textContent = stats.passwordsChecked || 0;
      $('#statBreaches').textContent = stats.breachesFound || 0;
      $('#statLastCheck').textContent = stats.lastCheckDate
        ? new Date(stats.lastCheckDate).toLocaleDateString()
        : 'Never';
    });
  }

  function initQuickAudit() {
    $('#quickAuditBtn').addEventListener('click', () => {
      chrome.runtime.sendMessage({ action: 'simulateAudit' }, response => {
        if (response && response.history && response.history.length > 0) {
          $$('.lg-tab').forEach(t => t.classList.remove('active'));
          $$('.lg-panel').forEach(p => p.classList.remove('active'));
          $$('.lg-tab')[1].classList.add('active');
          $('#panel-audit').classList.add('active');

          const history = response.history;
          const weakCount = history.filter(h => !h.breached).length;
          const breachedCount = history.filter(h => h.breached).length;

          let html = `
            <div class="lg-card">
              <div class="lg-audit-score">
                <div class="lg-audit-grade" style="color:${breachedCount > 0 ? 'var(--danger)' : 'var(--success)'}">
                  ${history.length} Passwords
                </div>
                <div class="lg-audit-score-label">
                  ${breachedCount} breached &middot; ${history.length - breachedCount} safe
                </div>
              </div>
              <div class="lg-audit-section">
                <div class="lg-audit-section-title">Password History</div>
                ${history.map(h => `
                  <div class="lg-audit-item ${h.breached ? 'lg-audit-item-critical' : ''}" style="border-left:3px solid ${h.breached ? 'var(--danger)' : 'var(--success)'}">
                    <strong>${escapeHtml(h.site)}</strong> - ${h.breached ? 'Breached' : 'Safe'} (${new Date(h.checkedAt).toLocaleDateString()})
                  </div>
                `).join('')}
              </div>
            </div>
          `;
          $('#auditResults').innerHTML = html;
          $('#auditResults').style.display = 'block';
        } else {
          $$('.lg-tab').forEach(t => t.classList.remove('active'));
          $$('.lg-panel').forEach(p => p.classList.remove('active'));
          $$('.lg-tab')[1].classList.add('active');
          $('#panel-audit').classList.add('active');
          $('#auditResults').innerHTML = '<div class="lg-card"><div class="lg-empty-state">No password history found. Check some passwords first.</div></div>';
          $('#auditResults').style.display = 'block';
        }
      });
    });
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str || '';
    return div.innerHTML;
  }

  document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initTheme();
    initCheck();
    initGenerator();
    initAudit();
    initHistory();
    initSettings();
    initNews();
    initQuickAudit();
    updateStats();
  });
})();
