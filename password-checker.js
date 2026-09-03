(() => {
  'use strict';

  const COMMON_PASSWORDS = new Set([
    'password','123456','12345678','qwerty','abc123','monkey','1234567','letmein',
    'trustno1','dragon','baseball','iloveyou','master','sunshine','ashley','bailey',
    'passw0rd','shadow','123123','654321','superman','qazwsx','michael','football',
    'password1','password123','123456789','1234567890','1234','000000','111111',
    'access','hello','charlie','donald','admin','login','welcome','starwars',
    'solo','princess','secret','batman','access123','loveme','fuckyou','whatever',
    'password!','pass','test','guest','master123','changeme','default','root',
    'toor','passpass','p@ssword','p@ssw0rd','pass123','pass1234','pass12345',
    'pass123456','Pass1','Pass12','Pass123','Pass1234','Password1','Password12',
    'Password123','qwerty123','qwerty1','qwert123','zxcvbnm','asdfghjkl',
    '1qaz2wsx','1q2w3e4r','1q2w3e','1q2w3e4r5t','123qwe','1234qwer',
    'abc1234','abcd1234','abcdef','abcdefg','abcdefgh','abcdefghi','1111','2222',
    '3333','4444','5555','6666','7777','8888','9999','0000','1212','1010',
    'love','sex','god','money','diamond','college','buster','thomas','hunter',
    'soccer','hockey','killer','george','andrew','jennifer','jordan','amanda',
    'summer','love123','angel1','babygirl','mylove','sweetie','beautiful',
    'ninja','mustang','camaro','ferrari','mercedes','porsche','mustang1',
    'hannah','jessica','ashley1','nicole','tiffany','maggie','daniel',
    'jessica1','nicole1','tiffany1','michael1','daniel1','jordan1','ashley123'
  ]);

  const SEQUENTIAL_PATTERNS = [
    /^(012|123|234|345|456|567|678|789|890)+$/i,
    /^(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)+$/i,
    /^(.)\1+$/,
    /^(01|10|23|32|45|54|67|76|89|98)+$/
  ];

  const KEYBOARD_PATTERNS = [
    'qwerty','asdfgh','zxcvbn','qazwsx','!@#$%^','qwertyuiop','asdfghjkl',
    '1qaz2wsx','2wsx3edc','3edc4rfv','!qaz@wsx','1q2w3e4r','qweasd',
    'qweasdzxc','zaq1xsw2','1234567890','-=[]\\;\',./',
    'azerty','azeasd','qsdfgh','wxcvbn'
  ];

  const LEET_MAP = {'4':'a','@':'a','3':'e','1':'i','!':'i','0':'o','$':'s','5':'s','7':'t','+':'t'};

  function deLeet(str) {
    return str.split('').map(c => LEET_MAP[c] || c).join('');
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
      if (!resp.ok) return { breached: false, count: 0, error: resp.status === 404 ? null : `API error ${resp.status}` };
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

  function calculateEntropy(password) {
    let charsetSize = 0;
    if (/[a-z]/.test(password)) charsetSize += 26;
    if (/[A-Z]/.test(password)) charsetSize += 26;
    if (/[0-9]/.test(password)) charsetSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;
    if (charsetSize === 0) return 0;
    return Math.floor(password.length * Math.log2(charsetSize));
  }

  function isSequential(password) {
    const lower = password.toLowerCase();
    for (const pattern of SEQUENTIAL_PATTERNS) {
      if (pattern.test(lower)) return true;
    }
    for (let i = 0; i < lower.length - 2; i++) {
      const c1 = lower.charCodeAt(i);
      const c2 = lower.charCodeAt(i + 1);
      const c3 = lower.charCodeAt(i + 2);
      if (c2 - c1 === 1 && c3 - c2 === 1) return true;
      if (c1 - c2 === 1 && c2 - c3 === 1) return true;
    }
    return false;
  }

  function isKeyboardPattern(password) {
    const lower = password.toLowerCase();
    const deleeted = deLeet(lower);
    for (const pattern of KEYBOARD_PATTERNS) {
      if (lower.includes(pattern) || deleeted.includes(pattern)) return true;
      if (lower.includes(pattern.split('').reverse().join(''))) return true;
    }
    return false;
  }

  function isCommonPassword(password) {
    const lower = password.toLowerCase();
    const deleeted = deLeet(lower);
    return COMMON_PASSWORDS.has(lower) || COMMON_PASSWORDS.has(deleeted);
  }

  function hasRepeatingChars(password) {
    return /(.)\1{2,}/.test(password);
  }

  function hasDictionaryWords(password) {
    const lower = password.toLowerCase();
    const commonWords = [
      'love','hate','home','work','game','play','fire','help','gold','star',
      'free','cool','nice','good','best','real','blue','pink','rock','moon',
      'sun','rain','snow','wind','dark','bone','king','lord','ace','hero'
    ];
    for (const word of commonWords) {
      if (lower.includes(word)) return true;
    }
    return false;
  }

  function calculateStrength(password) {
    if (!password) return { score: 0, label: 'None', color: '#ccc', details: [] };
    const details = [];
    let score = 0;
    const len = password.length;
    const entropy = calculateEntropy(password);
    score += Math.min(30, len * 2);
    score += Math.min(30, entropy / 2);
    if (/[a-z]/.test(password)) { score += 5; details.push('Lowercase letters'); }
    if (/[A-Z]/.test(password)) { score += 5; details.push('Uppercase letters'); }
    if (/[0-9]/.test(password)) { score += 5; details.push('Numbers'); }
    if (/[^a-zA-Z0-9]/.test(password)) { score += 10; details.push('Special characters'); }
    if (isSequential(password)) { score -= 25; details.push('Sequential pattern detected'); }
    if (isKeyboardPattern(password)) { score -= 20; details.push('Keyboard pattern detected'); }
    if (isCommonPassword(password)) { score -= 40; details.push('Common password'); }
    if (hasRepeatingChars(password)) { score -= 10; details.push('Repeating characters'); }
    if (hasDictionaryWords(password)) { score -= 10; details.push('Dictionary word found'); }
    if (len < 8) { score -= 15; details.push('Too short (min 8 chars)'); }
    score = Math.max(0, Math.min(100, score));
    let label, color;
    if (score < 25) { label = 'Very Weak'; color = '#dc3545'; }
    else if (score < 45) { label = 'Weak'; color = '#fd7e14'; }
    else if (score < 65) { label = 'Fair'; color = '#ffc107'; }
    else if (score < 85) { label = 'Strong'; color = '#20c997'; }
    else { label = 'Very Strong'; color = '#28a745'; }
    return { score, label, color, entropy, details };
  }

  function generateSecurePassword(length = 20) {
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const digits = '0123456789';
    const symbols = '!@#$%^&*()-_=+[]{}|;:,.<>?';
    const all = upper + lower + digits + symbols;
    const arr = new Uint32Array(length);
    crypto.getRandomValues(arr);
    let pw = '';
    pw += upper[arr[0] % upper.length];
    pw += lower[arr[1] % lower.length];
    pw += digits[arr[2] % digits.length];
    pw += symbols[arr[3] % symbols.length];
    for (let i = 4; i < length; i++) pw += all[arr[i] % all.length];
    return pw.split('').sort(() => Math.random() - 0.5).join('');
  }

  async function checkReused(hashes) {
    const map = {};
    for (const h of hashes) {
      if (!map[h]) map[h] = 0;
      map[h]++;
    }
    const reused = [];
    for (const [h, count] of Object.entries(map)) {
      if (count > 1) reused.push({ hash: h, count });
    }
    return reused;
  }

  window.LeakGuard = {
    sha1Hash,
    checkBreach,
    calculateStrength,
    calculateEntropy,
    generateSecurePassword,
    checkReused,
    isCommonPassword,
    isSequential,
    isKeyboardPattern
  };

  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
      if (msg.action === 'checkBreach') {
        checkBreach(msg.password).then(sendResponse);
        return true;
      }
      if (msg.action === 'calculateStrength') {
        sendResponse(calculateStrength(msg.password));
      }
      if (msg.action === 'generatePassword') {
        sendResponse({ password: generateSecurePassword(msg.length || 20) });
      }
    });
  }
})();
