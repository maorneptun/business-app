/**
 * mobile_fixes.js
 * הכנס את זה לפני </body> בקובץ index.html
 * מתקן: רשימת עובדים, חזרה, שגיאות, לקוחות
 */

// ===== 1. תצוגת שגיאות עם כפתור X =====
window.showError = function(msg) {
  const old = document.getElementById('_err_banner');
  if (old) old.remove();
  const el = document.createElement('div');
  el.id = '_err_banner';
  el.style.cssText = `
    position:fixed; top:16px; left:50%; transform:translateX(-50%);
    background:#d85a30; color:white; padding:12px 16px; border-radius:10px;
    font-size:13px; z-index:999; display:flex; align-items:center; gap:10px;
    max-width:90vw; box-shadow:0 4px 12px rgba(0,0,0,0.25);
    font-family:'Heebo',sans-serif; direction:rtl;
  `;
  el.innerHTML = `<span>⚠️ ${msg}</span>
    <button onclick="this.parentElement.remove()" style="
      background:rgba(255,255,255,0.25); border:none; color:white;
      width:24px; height:24px; border-radius:50%; cursor:pointer;
      font-size:14px; flex-shrink:0; display:flex; align-items:center; justify-content:center;
    ">✕</button>`;
  document.body.appendChild(el);
  setTimeout(() => { if (el.parentElement) el.remove(); }, 8000);
};

// ===== 2. תיקון select size=4 במובייל =====
function fixMobileSelects() {
  if (window.innerWidth > 700) return;
  const ids = ['abs-emp-sel', 'abs-replacement', 'edit-abs-repl-sel'];
  ids.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.removeAttribute('size');
      el.style.height = '44px';
      el.style.fontSize = '14px';
      el.style.webkitAppearance = 'none';
    }
  });
  // הסתר search inputs לפני select במובייל (כי keyboard עם select מבלבל)
  ['abs-emp-search', 'abs-repl-search', 'edit-abs-repl-search'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
  });
}

// ===== 3. ניווט חזרה =====
const _navHistory = [];

// עטוף את showPage המקורית
const _origShowPage = window.showPage;
window.showPage = function(name) {
  const activeEl = document.querySelector('.page.active');
  const prev = activeEl ? activeEl.id.replace('page-', '') : null;
  if (prev && prev !== name) _navHistory.push(prev);
  _origShowPage(name);
  updateBackBtn();
};

window.goBack = function() {
  if (_navHistory.length > 0) {
    const prev = _navHistory.pop();
    _origShowPage(prev);
    updateBackBtn();
  }
};

function updateBackBtn() {
  const btn = document.getElementById('_back_btn');
  if (!btn) return;
  btn.style.display = (window.innerWidth <= 700 && _navHistory.length > 0) ? 'flex' : 'none';
}

// צור כפתור חזרה
function createBackBtn() {
  if (document.getElementById('_back_btn')) return;
  const btn = document.createElement('button');
  btn.id = '_back_btn';
  btn.innerHTML = '← חזור';
  btn.style.cssText = `
    display:none; position:fixed; top:10px; right:10px; z-index:250;
    background:white; border:1px solid #e2e4e9; border-radius:20px;
    padding:6px 14px; font-family:'Heebo',sans-serif; font-size:13px;
    color:#0f6e56; cursor:pointer; box-shadow:0 2px 8px rgba(0,0,0,0.1);
    align-items:center; gap:4px;
  `;
  btn.onclick = goBack;
  document.body.appendChild(btn);
}

// ===== 4. תיקון רשימת עובדים - badge חיסורים בלי תאריך =====
// הבעיה: absCount מראה תאריך — נבדוק ב-renderEmployees
// זה מגיע מכך שהפונקציה מחשבת נכון אבל ה-badge מציג מספר שגוי
// הפתרון: נוסיף override לhook אחרי renderEmployees

const _origRenderEmployees = window.renderEmployees;
window.renderEmployees = function() {
  _origRenderEmployees();
  // תיקון אחרי הרינדור: הסר תאריכים מ-badges
  document.querySelectorAll('.badge.badge-red').forEach(badge => {
    const text = badge.textContent;
    // אם יש מספר ואחריו "חיסורים" — בסדר. אם יש תאריך — נקה
    if (/\d{1,2}\/\d{1,2}/.test(text)) {
      badge.remove();
    }
  });
  // תיקון מובייל selects
  fixMobileSelects();
};

// ===== 5. תיקון loadGreenInvoiceClients - שגיאה עם showError =====
const _origLoadClients = window.loadGreenInvoiceClients;
window.loadGreenInvoiceClients = async function() {
  const statusEl = document.getElementById('clients-load-status');
  if (statusEl) statusEl.innerHTML = '<span style="color:var(--text-muted)">טוען...</span>';

  const API = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
    ? 'https://business-app-hf5y.onrender.com'
    : '';

  try {
    const res = await fetch(`${API}/api/clients`, {
      signal: AbortSignal.timeout ? AbortSignal.timeout(10000) : undefined
    });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();
    const arr = Array.isArray(data) ? data : (data.items || data.clients || []);

    if (arr.length === 0) {
      if (statusEl) statusEl.innerHTML = '<span style="color:var(--warning)">⚠️ אין לקוחות בחשבונית ירוקה</span>';
      showError('לא נמצאו לקוחות בחשבונית ירוקה — בדוק שיש לקוחות במערכת');
      return;
    }

    applyClientsToUI(arr);
    localStorage.setItem('nep_gi_clients', JSON.stringify(arr));
    if (statusEl) statusEl.innerHTML = `<span style="color:var(--accent)">✅ ${arr.length} לקוחות</span>`;
    showToast(`נטענו ${arr.length} לקוחות`);

  } catch (err) {
    console.error('Clients error:', err);
    const msg = err.name === 'TimeoutError' ? 'השרת לא ענה — נסה שוב' : 'שגיאת חיבור לשרת';
    if (statusEl) statusEl.innerHTML = `<span style="color:var(--danger)">${msg} <button onclick="loadGreenInvoiceClients()" style="background:none;border:none;cursor:pointer;color:var(--accent);text-decoration:underline;font-size:11px;padding:0">נסה שנית</button></span>`;
    showError(msg + ' — ודא שהשרת פועל');
  }
};

// ===== 6. CSS נוסף למובייל =====
function addMobileCSS() {
  const style = document.createElement('style');
  style.textContent = `
    @media (max-width: 700px) {
      /* תיקון גובה modal */
      .modal { max-height: 88vh !important; overflow-y: auto; }
      /* select במובייל */
      .modal select.form-control {
        height: 44px;
        font-size: 14px;
        -webkit-appearance: none;
      }
      /* הסתר search inputs */
      #abs-emp-search, #abs-repl-search, #edit-abs-repl-search { display: none !important; }
      /* הגדל כפתורים */
      .btn { min-height: 40px; }
      /* תיקון bottom bar */
      .sidebar { padding-bottom: max(env(safe-area-inset-bottom), 8px); }
    }
  `;
  document.head.appendChild(style);
}

// ===== אתחול =====
document.addEventListener('DOMContentLoaded', function() {
  createBackBtn();
  addMobileCSS();
  fixMobileSelects();

  // תיקון: כשפותחים מודל — תקן selects
  document.querySelectorAll('.modal-overlay').forEach(overlay => {
    const observer = new MutationObserver(() => {
      if (overlay.classList.contains('open')) {
        setTimeout(fixMobileSelects, 100);
      }
    });
    observer.observe(overlay, { attributes: true, attributeFilter: ['class'] });
  });
});