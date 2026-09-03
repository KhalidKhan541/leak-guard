(() => {
  'use strict';

  const PROCESSED_ATTR = 'data-leak-guard-processed';
  const STRENGTH_ATTR = 'data-leak-guard-strength';
  const CHECKED_ATTR = 'data-leak-guard-checked';

  const observer = new MutationObserver(mutations => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeType === 1) processNode(node);
      }
    }
  });

  function processNode(root) {
    if (!root.querySelectorAll && !root.matches) return;
    if (root.matches && root.matches('input[type="password"]')) initPasswordField(root);
    const inputs = root.querySelectorAll ? root.querySelectorAll('input[type="password"]') : [];
    inputs.forEach(initPasswordField);
  }

  function initPasswordField(input) {
    if (input.getAttribute(PROCESSED_ATTR)) return;
    input.setAttribute(PROCESSED_ATTR, 'true');

    const wrapper = document.createElement('div');
    wrapper.style.position = 'relative';
    wrapper.style.display = 'inline-block';
    wrapper.style.width = '100%';

    if (input.parentNode) {
      input.parentNode.insertBefore(wrapper, input);
      wrapper.appendChild(input);
    }

    createStrengthIndicator(wrapper, input);
    createGenerateButton(wrapper, input);

    let debounce;
    input.addEventListener('input', () => {
      clearTimeout(debounce);
      debounce = setTimeout(() => {
        updateStrength(wrapper, input);
        if (input.value.length >= 4) {
          checkBreachStatus(input.value, wrapper);
        }
      }, 500);
    });
  }

  function createStrengthIndicator(wrapper, input) {
    const indicator = document.createElement('div');
    indicator.className = 'leak-guard-strength-indicator leak-guard-strength-weak';
    indicator.textContent = '';
    indicator.style.display = 'none';
    wrapper.appendChild(indicator);

    const bar = document.createElement('div');
    bar.className = 'leak-guard-strength-bar';
    const fill = document.createElement('div');
    fill.className = 'leak-guard-strength-fill';
    bar.appendChild(fill);
    wrapper.appendChild(bar);
  }

  function createGenerateButton(wrapper, input) {
    const btn = document.createElement('button');
    btn.className = 'leak-guard-generate-btn';
    btn.textContent = 'Generate';
    btn.type = 'button';
    btn.addEventListener('click', e => {
      e.preventDefault();
      e.stopPropagation();
      const pw = generateSecurePassword(20);
      input.value = pw;
      input.setAttribute('type', 'text');
      setTimeout(() => input.setAttribute('type', 'password'), 3000);
      updateStrength(wrapper, input);
      checkBreachStatus(pw, wrapper);
      btn.textContent = 'Copied!';
      btn.classList.add('copied');
      navigator.clipboard.writeText(pw).catch(() => {});
      setTimeout(() => { btn.textContent = 'Generate'; btn.classList.remove('copied'); }, 2000);
    });
    wrapper.appendChild(btn);
  }

  function generateSecurePassword(len) {
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const digits = '0123456789';
    const symbols = '!@#$%^&*()-_=+[]{}|;:,.<>?';
    const all = upper + lower + digits + symbols;
    const arr = new Uint32Array(len);
    crypto.getRandomValues(arr);
    let pw = '';
    pw += upper[arr[0] % upper.length];
    pw += lower[arr[1] % lower.length];
    pw += digits[arr[2] % digits.length];
    pw += symbols[arr[3] % symbols.length];
    for (let i = 4; i < len; i++) pw += all[arr[i] % all.length];
    return pw.split('').sort(() => Math.random() - 0.5).join('');
  }

  function updateStrength(wrapper, input) {
    const pw = input.value;
    const indicator = wrapper.querySelector('.leak-guard-strength-indicator');
    const fill = wrapper.querySelector('.leak-guard-strength-fill');
    if (!pw) {
      indicator.style.display = 'none';
      fill.style.width = '0';
      return;
    }

    const score = calcStrengthScore(pw);
    indicator.style.display = 'block';
    indicator.className = 'leak-guard-strength-indicator';

    let label, color, width;
    if (score < 25) { label = 'Weak'; color = '#dc3545'; width = '20%'; indicator.classList.add('leak-guard-strength-weak'); }
    else if (score < 50) { label = 'Fair'; color = '#ffc107'; width = '45%'; indicator.classList.add('leak-guard-strength-fair'); }
    else if (score < 75) { label = 'Good'; color = '#28a745'; width = '70%'; indicator.classList.add('leak-guard-strength-good'); }
    else { label = 'Strong'; color = '#007bff'; width = '100%'; indicator.classList.add('leak-guard-strength-strong'); }

    indicator.textContent = label;
    fill.style.width = width;
    fill.style.background = color;
  }

  function calcStrengthScore(pw) {
    let score = 0;
    const len = pw.length;
    if (len >= 8) score += 15;
    if (len >= 12) score += 15;
    if (len >= 16) score += 10;
    if (len >= 20) score += 10;
    if (/[a-z]/.test(pw)) score += 10;
    if (/[A-Z]/.test(pw)) score += 10;
    if (/[0-9]/.test(pw)) score += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) score += 15;
    if (/(.)\1{2,}/.test(pw)) score -= 10;
    if (/^(012|123|234|345|456|567|678|789|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(pw)) score -= 10;
    return Math.max(0, Math.min(100, score));
  }

  async function checkBreachStatus(password, wrapper) {
    if (wrapper.querySelector('[data-leak-guard-checked]')) return;
    try {
      const sha1 = await sha1Hash(password);
      const prefix = sha1.substring(0, 5);
      const suffix = sha1.substring(5).toUpperCase();
      const resp = await fetch(`https://haveibeenpwned.com/api/v3/breachedpassword/${prefix}`, {
        headers: { 'Add-Padding': 'true' }
      });
      if (resp.ok) {
        const text = await resp.text();
        const lines = text.split('\n');
        for (const line of lines) {
          const [hashSuffix, count] = line.split(':');
          if (hashSuffix.trim() === suffix) {
            showBreachNotification(wrapper, parseInt(count, 10));
            return;
          }
        }
      }
    } catch (e) {
      // Silent fail - don't expose errors to page
    }
  }

  function showBreachNotification(wrapper, count) {
    const existing = wrapper.querySelector('.leak-guard-breach-notification');
    if (existing) existing.remove();

    const notif = document.createElement('div');
    notif.className = 'leak-guard-breach-notification';
    notif.innerHTML = `
      <button class="leak-guard-notif-close">&times;</button>
      <div class="leak-guard-notif-title">
        <svg class="leak-guard-banner-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
          <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
        Password Breached!
      </div>
      <div class="leak-guard-notif-text">
        This password has been found in <strong>${count.toLocaleString()}</strong> data breach${count !== 1 ? 'es' : ''}. 
        Change it immediately on this site and anywhere else you use it.
      </div>
    `;
    notif.querySelector('.leak-guard-notif-close').addEventListener('click', () => notif.remove());
    document.body.appendChild(notif);
    setTimeout(() => { if (notif.parentNode) notif.remove(); }, 15000);
  }

  async function sha1Hash(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-1', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }

  observer.observe(document.documentElement, { childList: true, subtree: true });
  processNode(document.documentElement);
})();
