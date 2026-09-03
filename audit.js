(() => {
  'use strict';

  const SEQUENTIAL_PATTERNS = [
    /^(012|123|234|345|456|567|678|789|890)+$/i,
    /^(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)+$/i,
    /^(.)\1+$/
  ];

  const KEYBOARD_ROWS = ['qwertyuiop','asdfghjkl','zxcvbnm','1234567890'];

  const COMMON_WORDS = [
    'password','admin','user','login','welcome','master','dragon','monkey',
    'letmein','shadow','sunshine','princess','football','batman','superman',
    'trustno1','iloveyou','access','hello','charlie','donald','google',
    'amazon','facebook','twitter','instagram','linkedin','github'
  ];

  const COMMON_PASSWORDS_SET = new Set([
    'password','123456','12345678','qwerty','abc123','monkey','1234567','letmein',
    'trustno1','dragon','baseball','iloveyou','master','sunshine','ashley','bailey',
    'passw0rd','shadow','123123','654321','superman','qazwsx','michael','football',
    'password1','password123','123456789','1234567890','1234','000000','111111',
    'access','hello','charlie','donald','admin','login','welcome','starwars',
    'solo','princess','secret','batman','access123','loveme','fuckyou','whatever',
    'password!','pass','test','guest','master123','changeme','default','root',
    'p@ssword','p@ssw0rd','pass123','pass1234','pass12345','pass123456',
    'qwerty123','1qaz2wsx','1q2w3e4r','123qwe','abc1234','abcdef','abcdefgh',
    'love','sex','god','money','diamond','college','buster','thomas','hunter',
    'soccer','hockey','killer','george','andrew','jennifer','jordan','amanda',
    'summer','angel1','babygirl','mylove','sweetie','beautiful','ninja',
    'mustang','camaro','ferrari','mercedes','porsche','hannah','jessica',
    'nicole','tiffany','maggie','daniel'
  ]);

  function deLeet(str) {
    const map = {'4':'a','@':'a','3':'e','1':'i','!':'i','0':'o','$':'s','5':'s','7':'t','+':'t'};
    return str.split('').map(c => map[c] || c).join('');
  }

  function checkWeakPassword(password) {
    const issues = [];
    const lower = password.toLowerCase();
    const deleeted = deLeet(lower);

    if (password.length < 8) issues.push({ severity: 'critical', message: 'Password is too short (under 8 characters)' });
    else if (password.length < 12) issues.push({ severity: 'warning', message: 'Password could be longer (under 12 characters)' });

    if (COMMON_PASSWORDS_SET.has(lower) || COMMON_PASSWORDS_SET.has(deleeted)) {
      issues.push({ severity: 'critical', message: 'Password is in the top common passwords list' });
    }

    let hasLower = false, hasUpper = false, hasDigit = false, hasSymbol = false;
    for (const c of password) {
      if (/[a-z]/.test(c)) hasLower = true;
      else if (/[A-Z]/.test(c)) hasUpper = true;
      else if (/[0-9]/.test(c)) hasDigit = true;
      else hasSymbol = true;
    }
    const variety = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;
    if (variety <= 1) issues.push({ severity: 'critical', message: 'Uses only one character type (letters/numbers/symbols)' });
    else if (variety === 2) issues.push({ severity: 'warning', message: 'Uses only two character types' });

    for (const pattern of SEQUENTIAL_PATTERNS) {
      if (pattern.test(lower)) { issues.push({ severity: 'critical', message: 'Contains sequential pattern' }); break; }
    }

    for (let i = 0; i < lower.length - 2; i++) {
      const c1 = lower.charCodeAt(i), c2 = lower.charCodeAt(i + 1), c3 = lower.charCodeAt(i + 2);
      if (c2 - c1 === 1 && c3 - c2 === 1) { issues.push({ severity: 'warning', message: 'Contains ascending sequence' }); break; }
      if (c1 - c2 === 1 && c2 - c3 === 1) { issues.push({ severity: 'warning', message: 'Contains descending sequence' }); break; }
    }

    if (/(.)\1{2,}/.test(password)) issues.push({ severity: 'warning', message: 'Contains repeated characters' });

    const keyboardLower = lower.split('').sort().join('');
    for (const row of KEYBOARD_ROWS) {
      if (lower.length >= 4 && row.includes(lower.substring(0, 4))) {
        issues.push({ severity: 'warning', message: 'Starts with keyboard pattern' });
        break;
      }
    }

    for (const word of COMMON_WORDS) {
      if (lower.includes(word) && word.length >= 4) {
        issues.push({ severity: 'info', message: `Contains common word "${word}"` });
        break;
      }
    }

    const hasCommonSub = ['123','abc','qwerty','admin','pass','test'].some(s => lower.includes(s) || deleeted.includes(s));
    if (hasCommonSub) issues.push({ severity: 'warning', message: 'Contains common substring pattern' });

    return {
      weak: issues.filter(i => i.severity === 'critical' || i.severity === 'warning').length > 0,
      issues
    };
  }

  function detectReuse(passwordHashes) {
    const hashCount = {};
    for (const entry of passwordHashes) {
      const h = entry.hash.toUpperCase();
      if (!hashCount[h]) hashCount[h] = [];
      hashCount[h].push(entry.site || entry.label || 'Unknown');
    }
    const reused = [];
    for (const [hash, sites] of Object.entries(hashCount)) {
      if (sites.length > 1) {
        reused.push({
          sites,
          count: sites.length,
          severity: sites.length > 3 ? 'critical' : 'warning'
        });
      }
    }
    return reused;
  }

  function detectOldPasswords(passwordEntries) {
    const now = Date.now();
    const old = [];
    const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000;
    const NINETY_DAYS = 90 * 24 * 60 * 60 * 1000;
    const ONE_YEAR = 365 * 24 * 60 * 60 * 1000;

    for (const entry of passwordEntries) {
      if (!entry.lastChanged) continue;
      const age = now - entry.lastChanged;
      if (age > ONE_YEAR) {
        old.push({ site: entry.site || entry.label || 'Unknown', age, severity: 'critical', message: 'Over 1 year old' });
      } else if (age > NINETY_DAYS) {
        old.push({ site: entry.site || entry.label || 'Unknown', age, severity: 'warning', message: 'Over 90 days old' });
      } else if (age > THIRTY_DAYS) {
        old.push({ site: entry.site || entry.label || 'Unknown', age, severity: 'info', message: 'Over 30 days old' });
      }
    }
    return old;
  }

  function calculateStrength(password) {
    if (!password) return 0;
    let score = 0;
    const len = password.length;
    score += Math.min(30, len * 2);
    let charsetSize = 0;
    if (/[a-z]/.test(password)) charsetSize += 26;
    if (/[A-Z]/.test(password)) charsetSize += 26;
    if (/[0-9]/.test(password)) charsetSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;
    const entropy = len * Math.log2(Math.max(charsetSize, 1));
    score += Math.min(30, entropy / 2);
    const lower = password.toLowerCase();
    const deleeted = deLeet(lower);
    if (COMMON_PASSWORDS_SET.has(lower) || COMMON_PASSWORDS_SET.has(deleeted)) score -= 40;
    for (const pattern of SEQUENTIAL_PATTERNS) {
      if (pattern.test(lower)) { score -= 25; break; }
    }
    if (/(.)\1{2,}/.test(password)) score -= 10;
    const variety = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter(r => r.test(password)).length;
    score += (variety - 1) * 5;
    return Math.max(0, Math.min(100, score));
  }

  function generateReport(auditData) {
    const { weakPasswords, reusedPasswords, oldPasswords, checkedBreaches } = auditData;
    const totalIssues = weakPasswords.reduce((a, b) => a + b.issues.filter(i => i.severity !== 'info').length, 0)
      + reusedPasswords.length
      + oldPasswords.length;

    let score = 100;
    score -= weakPasswords.length * 15;
    score -= reusedPasswords.length * 10;
    score -= oldPasswords.length * 5;
    score = Math.max(0, Math.min(100, score));

    let grade;
    if (score >= 90) grade = 'A+';
    else if (score >= 80) grade = 'A';
    else if (score >= 70) grade = 'B';
    else if (score >= 60) grade = 'C';
    else if (score >= 40) grade = 'D';
    else grade = 'F';

    return {
      score,
      grade,
      summary: {
        weakPasswords: weakPasswords.length,
        reusedPasswords: reusedPasswords.length,
        oldPasswords: oldPasswords.length,
        breachedPasswords: checkedBreaches.filter(b => b.breached).length,
        totalIssues
      },
      weakPasswords,
      reusedPasswords,
      oldPasswords,
      checkedBreaches,
      recommendations: generateRecommendations(weakPasswords, reusedPasswords, oldPasswords, checkedBreaches),
      generatedAt: Date.now()
    };
  }

  function generateRecommendations(weak, reused, old, breached) {
    const recs = [];
    if (weak.length > 0) recs.push({ priority: 'high', message: `${weak.length} password${weak.length !== 1 ? 's are' : ' is'} weak. Replace with passwords of at least 12 characters using mixed character types.` });
    if (reused.length > 0) recs.push({ priority: 'high', message: `${reused.length} password${reused.length !== 1 ? 's are' : ' is'} reused across multiple sites. Use a unique password for each account.` });
    if (breached.some(b => b.breached)) recs.push({ priority: 'critical', message: 'Some passwords appear in known data breaches. Change them immediately.' });
    if (old.length > 0) recs.push({ priority: 'medium', message: `${old.length} password${old.length !== 1 ? 's haven' : ' hasn'}t been changed in over 90 days. Consider rotating them.` });
    recs.push({ priority: 'info', message: 'Use a password manager to generate and store strong, unique passwords.' });
    recs.push({ priority: 'info', message: 'Enable two-factor authentication wherever possible.' });
    return recs;
  }

  function simulateAudit(passwordEntries) {
    const weakPasswords = [];
    const reusedInputs = [];
    const oldPasswords = [];
    const checkedBreaches = [];

    for (const entry of passwordEntries) {
      const result = checkWeakPassword(entry.password);
      if (result.weak) {
        weakPasswords.push({
          site: entry.site || entry.label || 'Unknown',
          issues: result.issues,
          strengthScore: calculateStrength(entry.password)
        });
      }
      reusedInputs.push({
        hash: entry.hash || '',
        site: entry.site || entry.label || 'Unknown'
      });
      if (entry.lastChanged) {
        oldPasswords.push({ site: entry.site || entry.label || 'Unknown', lastChanged: entry.lastChanged });
      }
      if (entry.breachResult) {
        checkedBreaches.push({
          site: entry.site || entry.label || 'Unknown',
          breached: entry.breachResult.breached,
          count: entry.breachResult.count || 0
        });
      }
    }

    const reused = detectReuse(reusedInputs);
    const old = detectOldPasswords(oldPasswords.map((e, i) => ({
      ...e,
      lastChanged: passwordEntries[i] ? passwordEntries[i].lastChanged : null
    })));

    return generateReport({ weakPasswords, reusedPasswords: reused, oldPasswords: old, checkedBreaches });
  }

  window.LeakGuardAudit = {
    checkWeakPassword,
    detectReuse,
    detectOldPasswords,
    calculateStrength,
    generateReport,
    simulateAudit
  };

  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
      if (msg.action === 'auditPasswords') {
        sendResponse(simulateAudit(msg.passwords || []));
      }
      if (msg.action === 'checkWeakPassword') {
        sendResponse(checkWeakPassword(msg.password));
      }
      if (msg.action === 'detectReuse') {
        sendResponse(detectReuse(msg.hashes || []));
      }
      if (msg.action === 'detectOldPasswords') {
        sendResponse(detectOldPasswords(msg.entries || []));
      }
    });
  }
})();
